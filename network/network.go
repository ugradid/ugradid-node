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

package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/ugradid/ugradid-node/core"
	"github.com/ugradid/ugradid-node/crypto"
	"github.com/ugradid/ugradid-node/crypto/hash"
	"github.com/ugradid/ugradid-node/db"
	"github.com/ugradid/ugradid-node/network/dag"
	"github.com/ugradid/ugradid-node/network/log"
	"github.com/ugradid/ugradid-node/network/transport"
	"github.com/ugradid/ugradid-node/network/transport/grpc"
	v1 "github.com/ugradid/ugradid-node/network/transport/v1"
	"github.com/ugradid/ugradid-node/network/transport/v1/p2p"
	"github.com/ugradid/ugradid-node/vdr/types"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// ModuleName specifies the name of this module.
	ModuleName = "network"
)

type Network struct {
	config                 Config
	lastTransactionTracker lastTransactionTracker
	protocols              []transport.Protocol
	connectionManager      transport.ConnectionManager
	graph                  dag.Dag
	publisher              dag.Publisher
	payloadStore           dag.PayloadStore
	startTime              atomic.Value
	keyResolver            types.KeyResolver
	peerID                 transport.PeerId
	db                     db.BboltDatabase
}

func NewNetworkInstance(db db.BboltDatabase, config Config, keyResolver types.KeyResolver) *Network {
	result := &Network{
		db:                     db,
		config:                 config,
		keyResolver:            keyResolver,
		lastTransactionTracker: lastTransactionTracker{headRefs: make(map[hash.SHA256Hash]bool, 0)},
	}
	return result
}

// Configure configures the Network subsystem
func (n *Network) Configure(config core.ServerConfig) error {

	n.graph = dag.NewBBoltDAG(n.db, dag.NewSigningTimeVerifier(), dag.NewPrevTransactionsVerifier(), dag.NewTransactionSignatureVerifier(n.keyResolver))
	n.payloadStore = dag.NewBBoltPayloadStore(n.db)
	n.publisher = dag.NewReplayingDAGPublisher(n.payloadStore, n.graph)
	n.peerID = transport.PeerId(uuid.New().String())

	// TLS
	var clientCert tls.Certificate
	var trustStore *core.TrustStore
	if n.config.EnableTLS {
		var err error
		clientCert, trustStore, err = loadCertificateAndTrustStore(n.config)
		if err != nil {
			return err
		}
	} else if len(n.config.CertFile) > 0 || len(n.config.CertKeyFile) > 0 {
		log.Logger().Warn("TLS is disabled but CertFile and/or CertKeyFile is set. Did you really mean to disable TLS?")
	}

	// Configure protocols
	v1Cfg := p2p.AdapterConfig{
		PeerID:        n.peerID,
		ListenAddress: n.config.GrpcAddr,
	}
	if n.config.EnableTLS {
		v1Cfg.ClientCert = clientCert
		v1Cfg.TrustStore = trustStore.CertPool
	}
	n.protocols = []transport.Protocol{
		v1.New(n.config.ProtocolV1, v1Cfg, n.graph, n.publisher, n.payloadStore),
	}
	for _, prot := range n.protocols {
		err := prot.Configure()
		if err != nil {
			return err
		}
	}

	// Setup connection manager, load with bootstrap nodes
	if n.connectionManager == nil {
		var grpcOpts []grpc.ConfigOption
		if n.config.EnableTLS {
			grpcOpts = append(grpcOpts, grpc.WithTLS(clientCert, trustStore, n.config.MaxCRLValidityDays))
		}
		n.connectionManager = grpc.NewGrpcConnectionManager(
			grpc.NewConfig(n.config.GrpcAddr, n.peerID, grpcOpts...),
			n.protocols...)
	}
	for _, bootstrapNode := range n.config.BootstrapNodes {
		if len(strings.TrimSpace(bootstrapNode)) == 0 {
			continue
		}
		log.Logger().Infof("Connect bootstrap node: %s", bootstrapNode)
		n.connectionManager.Connect(bootstrapNode)
	}
	return nil
}

func loadCertificateAndTrustStore(moduleConfig Config) (tls.Certificate, *core.TrustStore, error) {
	clientCertificate, err := tls.LoadX509KeyPair(moduleConfig.CertFile, moduleConfig.CertKeyFile)
	if err != nil {
		return tls.Certificate{}, nil, errors.Wrapf(err, "unable to load node TLS client certificate (certfile=%s,certkeyfile=%s)", moduleConfig.CertFile, moduleConfig.CertKeyFile)
	}
	trustStore, err := core.LoadTrustStore(moduleConfig.TrustStoreFile)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return clientCertificate, trustStore, nil
}

// Name returns the module name.
func (n *Network) Name() string {
	return ModuleName
}

// Config returns a pointer to the actual config of the module.
func (n *Network) Config() interface{} {
	return &n.config
}

// Start initiates the Network subsystem
func (n *Network) Start() error {

	n.startTime.Store(time.Now())
	n.publisher.Subscribe(dag.AnyPayloadType, n.lastTransactionTracker.process)
	n.publisher.Start()

	if err := n.graph.Verify(context.Background()); err != nil {
		return err
	}

	err := n.connectionManager.Start()
	if err != nil {
		return err
	}
	for _, prot := range n.protocols {
		err := prot.Start()
		if err != nil {
			return err
		}
	}

	return nil
}

// Shutdown cleans up any leftover go routines
func (n *Network) Shutdown() error {
	var protocolErrors []error
	for _, prot := range n.protocols {
		err := prot.Stop()
		if err != nil {
			protocolErrors = append(protocolErrors, err)
		}
	}
	if len(protocolErrors) > 0 {
		return fmt.Errorf("unable to stop one or more protocols: %v", protocolErrors)
	}
	return nil
}

// Subscribe makes a subscription for the specified transaction type. The receiver is called when a transaction
// is received for the specified type.
func (n *Network) Subscribe(transactionType string, receiver dag.Receiver) {
	n.publisher.Subscribe(transactionType, receiver)
}

// GetTransaction retrieves the transaction for the given reference. If the transaction is not known, an error is returned.
func (n *Network) GetTransaction(transactionRef hash.SHA256Hash) (dag.Transaction, error) {
	return n.graph.Get(context.Background(), transactionRef)
}

// GetTransactionPayload retrieves the transaction payload for the given transaction. If the transaction or payload is not found
// nil is returned.
func (n *Network) GetTransactionPayload(transactionRef hash.SHA256Hash) ([]byte, error) {
	transaction, err := n.graph.Get(context.Background(), transactionRef)
	if err != nil {
		return nil, err
	}
	if transaction == nil {
		return nil, nil
	}
	return n.payloadStore.ReadPayload(context.Background(), transaction.PayloadHash())
}

// ListTransactions returns all transactions known to this Network instance.
func (n *Network) ListTransactions() ([]dag.Transaction, error) {
	return n.graph.FindBetween(context.Background(), dag.MinTime(), dag.MaxTime())
}

// CreateTransaction creates a new transaction with the specified payload, and signs it using the specified key.
// If the key should be inside the transaction (instead of being referred to) `attachKey` should be true.
func (n *Network) CreateTransaction(payloadType string, payload []byte, key crypto.Key, attachKey bool, timestamp time.Time, additionalPrevs []hash.SHA256Hash) (dag.Transaction, error) {
	payloadHash := hash.SHA256Sum(payload)
	log.Logger().Debugf("Creating transaction (payload hash=%s,type=%s,length=%d,signingKey=%s)", payloadHash, payloadType, len(payload), key.KID())

	// Assert that all additional prevs are present and its payload is there
	ctx := context.Background()
	for _, prev := range additionalPrevs {
		isPresent, err := n.isPayloadPresent(ctx, prev)
		if err != nil {
			return nil, err
		}
		if !isPresent {
			return nil, fmt.Errorf("additional prev is unknown or missing payload (prev=%s)", prev)
		}
	}

	// Create transaction
	prevs := n.lastTransactionTracker.heads()
	for _, addPrev := range additionalPrevs {
		prevs = append(prevs, addPrev)
	}
	unsignedTransaction, err := dag.NewTransaction(payloadHash, payloadType, prevs)
	if err != nil {
		return nil, fmt.Errorf("unable to create new transaction: %w", err)
	}
	// Sign it
	var transaction dag.Transaction
	var signer dag.TransactionSigner
	signer = dag.NewTransactionSigner(key, attachKey)
	transaction, err = signer.Sign(unsignedTransaction, timestamp)
	if err != nil {
		return nil, fmt.Errorf("unable to sign newly created transaction: %w", err)
	}
	// Store on local DAG and publish it
	if err = n.graph.Add(ctx, transaction); err != nil {
		return nil, fmt.Errorf("unable to add newly created transaction to DAG: %w", err)
	}
	if err = n.payloadStore.WritePayload(ctx, payloadHash, payload); err != nil {
		return nil, fmt.Errorf("unable to store payload of newly created transaction: %w", err)
	}
	log.Logger().Infof("Transaction created (ref=%s,type=%s,length=%d)", transaction.Ref(), payloadType, len(payload))
	return transaction, nil
}

func (n *Network) isPayloadPresent(ctx context.Context, txRef hash.SHA256Hash) (bool, error) {
	tx, err := n.graph.Get(ctx, txRef)
	if err != nil {
		return false, err
	}
	if tx == nil {
		return false, nil
	}
	return n.payloadStore.IsPresent(ctx, tx.PayloadHash())
}

// lastTransactionTracker that is used for tracking the heads but with payloads, since the DAG heads might have the associated payloads.
// This works because the publisher only publishes transactions which' payloads are present.
type lastTransactionTracker struct {
	headRefs map[hash.SHA256Hash]bool
	mux      sync.Mutex
}

func (l *lastTransactionTracker) process(transaction dag.Transaction, _ []byte) error {
	l.mux.Lock()
	defer l.mux.Unlock()

	// Update heads: previous' transactions aren't heads anymore, this transaction becomes a head.
	for _, prev := range transaction.Previous() {
		delete(l.headRefs, prev)
	}
	l.headRefs[transaction.Ref()] = true
	return nil
}

func (l *lastTransactionTracker) heads() []hash.SHA256Hash {
	l.mux.Lock()
	defer l.mux.Unlock()

	var heads []hash.SHA256Hash
	for head := range l.headRefs {
		heads = append(heads, head)
	}
	return heads
}
