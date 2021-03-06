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

package transport

// Protocol is a self-contained process that can exchange network data
// (e.g. DAG transactions or private credentials) with other parties on the network.
type Protocol interface {
	// Configure configures the Protocol implementation, must be called before Start().
	Configure() error
	// Start starts the Protocol implementation.
	Start() error
	// Stop stops the Protocol implementation.
	Stop() error
	// Connect attempts to make an outbound connection to the given peer if it's not already connected.
	Connect(peerAddress string)
	// Peers returns a slice containing the peers that are currently connected.
	Peers() []Peer
}
