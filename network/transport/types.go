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

import "fmt"

// PeerId defines a peer's unique identifier.
type PeerId string

// String returns the PeerId as string.
func (p PeerId) String() string {
	return string(p)
}

// Peer holds the properties of a remote node we're connected to
type Peer struct {
	// ID holds the unique id of the peer
	Id PeerId
	// Address holds the remote address of the node we're actually connected to
	Address string
}

// String returns the peer as string.
func (p Peer) String() string {
	return fmt.Sprintf("%s@%s", p.Id, p.Address)
}


