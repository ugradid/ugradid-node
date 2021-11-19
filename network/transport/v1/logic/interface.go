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
	"errors"
	"github.com/ugradid/ugradid-node/crypto/hash"
	"github.com/ugradid/ugradid-node/network/transport"
	"time"
)

// Version holds the number of the version of this protocol implementation.
const Version = 1

// ErrMissingProtocolVersion is used when a message is received without protocol version.
var ErrMissingProtocolVersion = errors.New("missing protocol version")

// ErrUnsupportedProtocolVersion is used when a message is received with an unsupported protocol version.
var ErrUnsupportedProtocolVersion = errors.New("unsupported protocol version")

// Protocol defines the API for the protocol layer, which is a high-level interface to interact with the network. It responds
// from (peer) messages received through the P2P layer.
type Protocol interface {
	// Configure configures the Protocol. Must be called before Start().
	Configure(advertHashesInterval time.Duration, advertDiagnosticsInterval time.Duration,
		collectMissingPayloadsInterval time.Duration, peerID transport.PeerId)
	// Start the Protocol (sending and receiving of messages).
	Start()
	// Stop the Protocol.
	Stop()
}

// PeerOmnihashQueue is a queue which contains the omnihashes (DAG reduced to a single hash) from our peers.
type PeerOmnihashQueue interface {
	// Get blocks until there's an PeerOmnihash available and returns it.
	Get() *PeerOmnihash
}

// PeerOmnihash describes a peer and its DAG reduced to a single hash.
type PeerOmnihash struct {
	// Peer holds the ID of the peer we got the hash from.
	Peer transport.PeerId
	// Hash holds the actual hash.
	Hash hash.SHA256Hash
}