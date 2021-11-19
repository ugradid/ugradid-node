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
	"crypto/tls"
	"crypto/x509"
	"github.com/ugradid/ugradid-node/core"
	"github.com/ugradid/ugradid-node/crl"
	"github.com/ugradid/ugradid-node/network/transport"
)

// ConfigOption is used to build Config.
type ConfigOption func(config *Config)

// NewConfig creates a new Config, used for configuring a gRPC ConnectionManager.
func NewConfig(grpcAddress string, peerID transport.PeerId, options ...ConfigOption) Config {
	cfg := Config{
		ListenAddress: grpcAddress,
		peerId:        peerID,
	}
	for _, opt := range options {
		opt(&cfg)
	}
	return cfg
}

// WithTLS enables TLS for gRPC ConnectionManager.
func WithTLS(clientCertificate tls.Certificate, trustStore *core.TrustStore, maxCRLValidityDays int) ConfigOption {
	return func(config *Config) {
		config.ClientCert = clientCertificate
		config.TrustStore = trustStore.CertPool
		config.CRLValidator = crl.NewValidator(trustStore.Certificates())
		config.MaxCRLValidityDays = maxCRLValidityDays
		// Load TLS server certificate, only if enableTLS=true and gRPC server should be started.
		if config.ListenAddress != "" {
			config.ServerCert = config.ClientCert
		}
	}
}

// Config holds values for configuring the gRPC ConnectionManager.
type Config struct {
	// PeerID contains the ID of the local node.
	peerId transport.PeerId
	// ListenAddress specifies the socket address the gRPC server should listen on.
	ListenAddress string
	// ClientCert specifies the TLS client certificate. If set the client should open a TLS socket, otherwise plain TCP.
	ClientCert tls.Certificate
	// ServerCert specifies the TLS server certificate. If set the server should open a TLS socket, otherwise plain TCP.
	ServerCert tls.Certificate
	// TrustStore contains the trust anchors used when verifying remote a peer's TLS certificate.
	TrustStore *x509.CertPool
	// CRLValidator contains the database for revoked certificates
	CRLValidator crl.Validator
	// MaxCRLValidityDays contains the number of days that a CRL can be outdated
	MaxCRLValidityDays int
}

func (cfg Config) tlsEnabled() bool {
	return cfg.TrustStore != nil
}
