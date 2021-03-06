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

package p2p

import (
	"fmt"
	"github.com/ugradid/ugradid-node/network/transport"
	"google.golang.org/grpc/metadata"
	"net"
	"strings"
)

const protocolVersionV1 = "v1"
const protocolVersionHeader = "version"
const peerIDHeader = "peerId"

func normalizeAddress(addr string) string {
	var normalizedAddr string
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		normalizedAddr = addr
	} else {
		if host == "localhost" {
			host = "127.0.0.1"
			normalizedAddr = net.JoinHostPort(host, port)
		} else {
			normalizedAddr = addr
		}
	}
	return normalizedAddr
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

func protocolVersionFromMetadata(md metadata.MD) (string, error) {
	values := md.Get(protocolVersionHeader)
	if len(values) == 0 {
		// no version means v1 for backwards compatibility
		return protocolVersionV1, nil
	} else if len(values) > 1 {
		return "", fmt.Errorf("peer sent multiple values for %s header", protocolVersionHeader)
	}
	return strings.TrimSpace(values[0]), nil
}

func constructMetadata(peerID transport.PeerId) metadata.MD {
	return metadata.New(map[string]string{
		peerIDHeader:          string(peerID),
		protocolVersionHeader: protocolVersionV1,
	})
}
