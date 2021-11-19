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

package logic

import (
	"github.com/sirupsen/logrus"
	"github.com/ugradid/ugradid-node/crypto/hash"
	"github.com/ugradid/ugradid-node/network/dag"
	"github.com/ugradid/ugradid-node/network/log"
	"github.com/ugradid/ugradid-node/network/transport"
	"github.com/ugradid/ugradid-node/network/transport/v1/p2p"
	"sync"
	"time"
)

// protocol is thread-safe when callers use the Protocol interface
type protocol struct {
	adapter      p2p.Adapter
	graph        dag.Dag
	payloadStore dag.PayloadStore
	sender       messageSender

	receivedPeerHashes        *chanPeerHashQueue
	receivedTransactionHashes *chanPeerHashQueue

	// peerOmnihashes contains the omnihashes of our peers. Access must be protected using peerOmnihashMutex
	peerOmnihashes      map[transport.PeerId]hash.SHA256Hash
	peerOmnihashChannel chan PeerOmnihash
	peerOmnihashMutex   *sync.Mutex

	blocks                  dagBlocks
	missingPayloadCollector missingPayloadCollector

	advertHashesInterval           time.Duration
	advertDiagnosticsInterval      time.Duration
	collectMissingPayloadsInterval time.Duration
	// peerID contains our own peer ID which can be logged for debugging purposes
	peerID    transport.PeerId
	publisher dag.Publisher
}

// NewProtocol creates a new instance of Protocol
func NewProtocol(adapter p2p.Adapter, graph dag.Dag, publisher dag.Publisher, payloadStore dag.PayloadStore) Protocol {
	p := &protocol{
		peerOmnihashes:       make(map[transport.PeerId]hash.SHA256Hash),
		peerOmnihashChannel:  make(chan PeerOmnihash, 100),
		peerOmnihashMutex:    &sync.Mutex{},
		blocks:               newDAGBlocks(),
		graph:                graph,
		payloadStore:         payloadStore,
		publisher:            publisher,
		adapter:              adapter,
	}
	return p
}

func (p *protocol) Configure(advertHashesInterval time.Duration, advertDiagnosticsInterval time.Duration, collectMissingPayloadsInterval time.Duration, peerID transport.PeerId) {
	p.advertHashesInterval = advertHashesInterval
	p.advertDiagnosticsInterval = advertDiagnosticsInterval
	p.collectMissingPayloadsInterval = collectMissingPayloadsInterval
	p.peerID = peerID
	p.sender = defaultMessageSender{p2p: p.adapter, maxMessageSize: p2p.MaxMessageSizeInBytes}
	p.missingPayloadCollector = broadcastingMissingPayloadCollector{
		graph:        p.graph,
		payloadStore: p.payloadStore,
		sender:       p.sender,
	}
	p.publisher.Subscribe(dag.AnyPayloadType, p.blocks.addTransaction)
}

func (p *protocol) Start() {
	go p.consumeMessages(p.adapter.ReceivedMessages())
	go p.startAdvertingHashes()
	go p.startCollectingMissingPayloads()
}

func (p protocol) Stop() {

}

func (p protocol) startAdvertingHashes() {
	ticker := time.NewTicker(p.advertHashesInterval)
	for {
		select {
		case <-ticker.C:
			p.sender.broadcastAdvertHashes(p.blocks.get())
		}
	}
}

func (p protocol) startCollectingMissingPayloads() {
	if p.collectMissingPayloadsInterval.Nanoseconds() == 0 {
		log.Logger().Info("Collecting missing payloads is disabled.")
		return
	}
	ticker := time.NewTicker(p.collectMissingPayloadsInterval)
	for {
		select {
		case <-ticker.C:
			err := p.missingPayloadCollector.findAndQueryMissingPayloads()
			if err != nil {
				logrus.Infof("Error occured while querying missing payloads: %s", err)
			}
		}
	}
}

func (p protocol) consumeMessages(queue p2p.MessageQueue) {
	for {
		peerMsg := queue.Get()
		if err := p.handleMessage(peerMsg); err != nil {
			log.Logger().Errorf("Error handling message (peer=%s): %v", peerMsg.Peer, err)
		}
	}
}

type chanPeerHashQueue struct {
	c chan *PeerOmnihash
}

func (q chanPeerHashQueue) Get() *PeerOmnihash {
	return <-q.c
}

func withLock(mux *sync.Mutex, fn func()) {
	mux.Lock()
	defer mux.Unlock()
	fn()
}

