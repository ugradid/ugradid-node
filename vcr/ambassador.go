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

package vcr

import (
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/ugradid/ugradid-common/vc"
	"github.com/ugradid/ugradid-common/vc/schema"
	"github.com/ugradid/ugradid-node/network"
	"github.com/ugradid/ugradid-node/network/dag"
	"github.com/ugradid/ugradid-node/vcr/credential"
	"github.com/ugradid/ugradid-node/vcr/log"
)

// Ambassador registers a callback with the network for processing received Verifiable Credentials.
type Ambassador interface {
	// Configure instructs the ambassador to start receiving DID Documents from the network.
	Configure()
}

type ambassador struct {
	networkClient network.Transactions
	writer        Writer
}

// NewAmbassador creates a new listener for the network that listens to Verifiable Credential transactions.
func NewAmbassador(networkClient network.Transactions, writer Writer) Ambassador {
	return ambassador{
		networkClient: networkClient,
		writer:        writer,
	}
}

// Configure instructs the ambassador to start receiving DID Documents from the network.
func (n ambassador) Configure() {
	n.networkClient.Subscribe(vcDocumentType, n.vcCallback)
	n.networkClient.Subscribe(revocationDocumentType, n.rCallback)
	n.networkClient.Subscribe(schemaDocumentType, n.schemaCallback)
}

// vcCallback gets called when new Verifiable Credentials are received by the network. All checks on the signature are already performed.
// The VCR is used to verify the contents of the credential.
// payload should be a json encoded vc.VerifiableCredential
func (n ambassador) vcCallback(tx dag.Transaction, payload []byte) error {
	log.Logger().Debugf("Processing VC received from network (ref=%s)", tx.Ref())

	target := vc.VerifiableCredential{}
	if err := json.Unmarshal(payload, &target); err != nil {
		return errors.Wrap(err, "credential processing failed")
	}

	// Verify and store
	return n.writer.StoreCredential(target)
}

// rCallback gets called when new credential revocations are received by the network. All checks on the signature are already performed.
// The VCR is used to verify the contents of the revocation.
// payload should be a json encoded Revocation
func (n ambassador) rCallback(tx dag.Transaction, payload []byte) error {
	log.Logger().Debugf("Processing VC revocation received from network (ref=%s)", tx.Ref())

	r := credential.Revocation{}
	if err := json.Unmarshal(payload, &r); err != nil {
		return errors.Wrap(err, "revocation processing failed")
	}

	// Verify and store
	return n.writer.StoreRevocation(r)
}

// schemaCallback gets called when new schema vc are received by the network.
func (n ambassador) schemaCallback(tx dag.Transaction, payload []byte) error {
	log.Logger().Debugf("Processing VC schema received from network (ref=%s)", tx.Ref())

	sc := schema.Schema{}
	if err := json.Unmarshal(payload, &sc); err != nil {
		return errors.Wrap(err, "schema processing failed")
	}

	// Verify and store
	return n.writer.StoreSchema(sc)
}