/*
 * Copyright (c) 2021 ugradid community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/pkg/errors"
	"github.com/ugradid/ugradid-node/network/log"
	"github.com/ugradid/ugradid-node/network/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	grpcPeer "google.golang.org/grpc/peer"
	"net"
	"strings"
	"sync"
)

const defaultMaxMessageSizeInBytes = 1024 * 512

const protocolVersionV1 = "v1"          // required for backwards compatibility with v1
const protocolVersionHeader = "version" // required for backwards compatibility with v1
const peerIDHeader = "peerId"

// MaxMessageSizeInBytes defines the maximum size of an in- or outbound gRPC/Protobuf message
var MaxMessageSizeInBytes = defaultMaxMessageSizeInBytes

// NewGrpcConnectionManager creates a new ConnectionManager that
// accepts/creates connections which communicate using the given protocols.
func NewGrpcConnectionManager(config Config, protocols ...transport.Protocol) transport.ConnectionManager {
	if len(protocols) > 1 {
		panic("GrpcConnectionManager: multiple protocols currently not supported")
	}

	return &grpcConnectionManager{
		protocols:       protocols,
		config:          config,
		connections:     &connectionList{},
		grpcServerMutex: &sync.Mutex{},
	}
}

// grpcConnectionManager is a ConnectionManager that does not discover peers on its own
type grpcConnectionManager struct {
	protocols       []transport.Protocol
	config          Config
	connections     *connectionList
	grpcServer      *grpc.Server
	grpcServerMutex *sync.Mutex
	listener        net.Listener
}

func (s *grpcConnectionManager) Start() error {
	s.grpcServerMutex.Lock()
	defer s.grpcServerMutex.Unlock()

	if s.config.ListenAddress != "" {
		log.Logger().Infof("Starting gRPC server on %s", s.config.ListenAddress)
		serverOpts := []grpc.ServerOption{
			grpc.MaxRecvMsgSize(MaxMessageSizeInBytes),
			grpc.MaxSendMsgSize(MaxMessageSizeInBytes),
		}
		var err error
		s.listener, err = net.Listen("tcp", s.config.ListenAddress)
		if err != nil {
			return err
		}
		// Configure TLS if enabled
		if s.config.tlsEnabled() {
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{s.config.ServerCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    s.config.TrustStore,
			}
			serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))

			// Configure support for checking revoked certificates
			s.config.CRLValidator.SyncLoop(context.TODO())
			s.config.CRLValidator.Configure(tlsConfig, s.config.MaxCRLValidityDays)
		} else {
			log.Logger().Info("TLS is disabled, make sure the node is behind a TLS terminator which performs TLS authentication.")
		}

		// Create gRPC server for inbound connectionList and associate it with the protocols
		s.grpcServer = grpc.NewServer(serverOpts...)
		for _, prot := range s.protocols {
			grpcProtocol, ok := prot.(ServiceImplementor)
			if ok {
				grpcProtocol.RegisterService(s, s.acceptGRPCStream)
			}
		}

		// Start serving from the gRPC server
		go func(server *grpc.Server, listener net.Listener) {
			err := server.Serve(listener)
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				log.Logger().Errorf("gRPC server errored: %v", err)
				s.Stop()
			}
		}(s.grpcServer, s.listener)
	} else {
		log.Logger().Info("Not starting gRPC server, connections will only be outbound.")
	}
	return nil
}

func (s grpcConnectionManager) Stop() {
	s.connections.closeAll()

	s.grpcServerMutex.Lock()
	defer s.grpcServerMutex.Unlock()

	// Stop gRPC server
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
		s.grpcServer = nil
	}
	// Stop TCP listener
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			log.Logger().Warn("Error while closing server listener: ", err)
		}
		s.listener = nil
	}
}

func (s grpcConnectionManager) Connect(peerAddress string) {
	s.protocols[0].Connect(peerAddress)
}

func (s grpcConnectionManager) Peers() []transport.Peer {
	return s.protocols[0].Peers()
}

func (s grpcConnectionManager) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	s.grpcServer.RegisterService(desc, impl)
}

func readHeaders(metadata metadata.MD) (transport.PeerId, error) {
	serverPeerID, err := peerIDFromMetadata(metadata)
	if err != nil {
		return "", fmt.Errorf("unable to parse PeerID: %w", err)
	}
	if serverPeerID == "" {
		return "", errors.New("peer didn't sent a PeerID")
	}

	return serverPeerID, nil
}

func (s *grpcConnectionManager) acceptGRPCStream(stream grpc.ServerStream) (bool, transport.Peer, chan struct{}) {
	peerCtx, _ := grpcPeer.FromContext(stream.Context())
	log.Logger().Tracef("New peer connected from %s", peerCtx.Addr)

	// Build peer info
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		log.Logger().Errorf("Unable to accept gRPC stream (remote address: %s): unable to read metadata", peerCtx.Addr)
		return false, transport.Peer{}, nil
	}
	peerID, err := readHeaders(md)
	if err != nil {
		log.Logger().Errorf("Unable to accept gRPC stream (remote address: %s), unable to read peer ID: %v", peerCtx.Addr, err)
		return false, transport.Peer{}, nil
	}
	peer := transport.Peer{
		Id:      peerID,
		Address: peerCtx.Addr.String(),
	}

	// Check already connected?
	if s.connections.connected(peerID) {
		log.Logger().Infof("Rejecting connection, peer already connected: %s", peer)
		return false, peer, nil
	}

	log.Logger().Infof("New peer connected (peer=%s)", peer)
	// We received our peer's PeerID, now send our own.
	if err := stream.SendHeader(constructMetadata(s.config.peerId)); err != nil {
		log.Logger().Errorf("Unable to accept gRPC stream (remote address: %s), unable to send headers: %v", peerCtx.Addr, err)
		return false, transport.Peer{}, nil
	}

	connection := s.connections.getOrRegister(peer)
	connection.registerServerStream(stream)
	return true, peer, connection.closer()
}

func peerIDFromMetadata(md metadata.MD) (transport.PeerId, error) {
	values := md.Get(peerIDHeader)
	if len(values) == 0 {
		return "", fmt.Errorf("peer didn't send %s header", peerIDHeader)
	} else if len(values) > 1 {
		return "", fmt.Errorf("peer sent multiple values for %s header", peerIDHeader)
	}
	peerID := transport.PeerId(strings.TrimSpace(values[0]))
	if peerID == "" {
		return "", fmt.Errorf("peer sent empty %s header", peerIDHeader)
	}
	return peerID, nil
}

func constructMetadata(peerID transport.PeerId) metadata.MD {
	return metadata.New(map[string]string{
		peerIDHeader:          string(peerID),
		protocolVersionHeader: protocolVersionV1, // required for backwards compatibility with v1
	})
}
