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

import "github.com/ugradid/ugradid-node/network/transport/v1"

type Config struct {
	// Socket address for gRPC to listen on
	GrpcAddr string `koanf:"network.grpcaddr"`
	// File name store
	File string `koanf:"network.file"`
	// EnableTLS specifies whether to enable TLS for incoming connections.
	EnableTLS bool `koanf:"network.enabletls"`
	// Public address of this nodes other nodes can use to connect to this node.
	BootstrapNodes []string `koanf:"network.bootstrapnodes"`
	// Crypto files
	CertFile       string `koanf:"network.certfile"`
	CertKeyFile    string `koanf:"network.certkeyfile"`
	TrustStoreFile string `koanf:"network.truststorefile"`
	// MaxCRLValidityDays defines the number of days a CRL can be outdated, after that it will hard-fail
	MaxCRLValidityDays int `koanf:"network.maxcrlvaliditydays"`
	// ProtocolV1 specifies config for protocol v1
	ProtocolV1 v1.Config `koanf:"network.v1"`
}

// DefaultConfig returns the default NetworkEngine configuration.
func DefaultConfig() Config {
	return Config{
		GrpcAddr:   ":5555",
		File:       "dag.db",
		ProtocolV1: v1.DefaultConfig(),
		EnableTLS:  true,
	}
}
