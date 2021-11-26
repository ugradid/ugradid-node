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
	"encoding/base64"
	"encoding/json"
	"fmt"
	ssi "github.com/ugradid/ugradid-common"
	"github.com/ugradid/ugradid-common/did"
	"github.com/ugradid/ugradid-common/vc"
	"github.com/ugradid/ugradid-common/vc/schema"
	"github.com/ugradid/ugradid-node/crypto"
	"github.com/ugradid/ugradid-node/crypto/hash"
	"github.com/ugradid/ugradid-node/vcr/log"
	schema2 "github.com/ugradid/ugradid-node/vcr/schema"
	doc2 "github.com/ugradid/ugradid-node/vdr/doc"
)

func (c *vcr) Create(template schema.Schema) (*schema.Schema, error) {

	validator, err := schema2.FindValidator(template.Schema)
	if err != nil {
		return nil, err
	}

	sc := schema.Schema{
		Name:   template.Name,
		Author: template.Author,
		Schema: template.Schema,
	}

	// find issuer
	author, err := did.ParseDID(sc.Author.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse author: %w", err)
	}

	// find did document/metadata for originating TXs
	doc, meta, err := c.docResolver.Resolve(*author, nil)
	if err != nil {
		return nil, err
	}

	// resolve an assertionMethod key for issuer
	kid, err := doc2.ExtractAssertionKeyID(*doc)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}

	key, err := c.keyStore.Resolve(kid.String())
	if err != nil {
		return nil, fmt.Errorf("could not resolve kid: %w", err)
	}

	// set defaults
	if err := schema2.FillSchema(&sc); err != nil {
		return nil, fmt.Errorf("failed fill schema: %w", err)
	}

	// sign
	if err := c.generateSchemaProof(&sc, kid, key); err != nil {
		return nil, fmt.Errorf("failed to generate credential proof: %w", err)
	}

	// do same validation as network nodes
	if err := validator.Validate(sc); err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(sc)

	_, err = c.network.CreateTransaction(
		schemaDocumentType, payload, key, false, sc.Authored, meta.SourceTransactions)

	if err != nil {
		return nil, fmt.Errorf("failed to publish schema: %w", err)
	}

	log.Logger().Infof(
		"Verifiable Credential schema created (id=%s,version=%s)", sc.ID, sc.Version)

	return &sc, nil
}

func (c *vcr) verifySchema(sc schema.Schema) error {
	// it must have valid content
	validator, err := schema2.FindValidator(sc.Schema)
	if err != nil {
		return err
	}

	if err := validator.Validate(sc); err != nil {
		return err
	}

	// create correct challenge for verification
	payload := generateSchemaChallenge(sc)

	return c.verifyProof(payload, sc.Author, sc.Proof, &sc.Authored)
}

func generateSchemaChallenge(sc schema.Schema) []byte {
	// without JWS
	proof := sc.Proof.Proof

	// payload
	sc.Proof = nil
	payload, _ := json.Marshal(sc)

	// proof
	prJSON, _ := json.Marshal(proof)

	sums := append(hash.SHA256Sum(prJSON).Slice(), hash.SHA256Sum(payload).Slice()...)
	tbs := base64.RawURLEncoding.EncodeToString(sums)

	return []byte(tbs)
}

func (c *vcr) generateSchemaProof(sc *schema.Schema, kid ssi.URI, key crypto.Key) error {
	// create proof
	sc.Proof = &vc.JSONWebSignature2020Proof{
		Proof: vc.Proof{
			Type:               "JsonWebSignature2020",
			ProofPurpose:       "assertionMethod",
			VerificationMethod: kid,
			Created:            sc.Authored,
		},
	}

	// create correct signing challenge
	challenge := generateSchemaChallenge(*sc)

	sig, err := crypto.SignJWS(challenge, detachedJWSHeaders(), key.Signer())
	if err != nil {
		return err
	}

	// remove payload from sig since a detached jws is required.
	dsig := toDetachedSignature(sig)

	sc.Proof.Jws = dsig

	return nil
}
