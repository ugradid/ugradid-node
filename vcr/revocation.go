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
	"errors"
	"fmt"
	ssi "github.com/ugradid/ugradid-common"
	"github.com/ugradid/ugradid-common/did"
	"github.com/ugradid/ugradid-common/vc"
	"github.com/ugradid/ugradid-node/crypto"
	"github.com/ugradid/ugradid-node/crypto/hash"
	"github.com/ugradid/ugradid-node/vcr/credential"
	"github.com/ugradid/ugradid-node/vcr/log"
	doc2 "github.com/ugradid/ugradid-node/vdr/doc"
)

func (c *vcr) Revoke(ID ssi.URI, credentialType string) (*credential.Revocation, error) {
	// first find it using a query on id.
	target, err := c.GetCredential(ID, credentialType)
	if err != nil {
		// not found and other errors
		return nil, err
	}

	// already revoked, return error
	conflict, err := c.isRevoked(ID)
	if err != nil {
		return nil, err
	}
	if conflict {
		return nil, ErrRevoked
	}

	// find issuer
	issuer, err := did.ParseDID(target.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to extract issuer: %w", err)
	}

	// find did document/metadata for originating TXs
	doc, meta, err := c.docResolver.Resolve(*issuer, nil)
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
	r := credential.BuildRevocation(target)

	// sign
	if err = c.generateRevocationProof(&r, kid, key); err != nil {
		return nil, fmt.Errorf("failed to generate revocation proof: %w", err)
	}

	// do same validation as network nodes
	if err := credential.ValidateRevocation(r); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	payload, _ := json.Marshal(r)

	_, err = c.network.CreateTransaction(revocationDocumentType, payload, key, false, r.Date, meta.SourceTransactions)
	if err != nil {
		return nil, fmt.Errorf("failed to publish revocation: %w", err)
	}

	log.Logger().Infof("Verifiable Credential revoked (id=%s)", target.ID)

	return &r, nil
}

func (c *vcr) generateRevocationProof(r *credential.Revocation, kid ssi.URI, key crypto.Key) error {
	// create proof
	r.Proof = &vc.JSONWebSignature2020Proof{
		Proof: vc.Proof{
			Type:               "JsonWebSignature2020",
			ProofPurpose:       "assertionMethod",
			VerificationMethod: kid,
			Created:            r.Date,
		},
	}

	// create correct signing challenge
	challenge := generateRevocationChallenge(*r)

	sig, err := crypto.SignJWS(challenge, detachedJWSHeaders(), key.Signer())
	if err != nil {
		return err
	}

	// remove payload from sig since a detached jws is required.
	dsig := toDetachedSignature(sig)

	r.Proof.Jws = dsig

	return nil
}

func (c *vcr) verifyRevocation(r credential.Revocation) error {
	// it must have valid content
	if err := credential.ValidateRevocation(r); err != nil {
		return err
	}

	// issuer must be the same as vc issuer
	subject := r.Subject
	subject.Fragment = ""
	if subject != r.Issuer {
		return errors.New("issuer of revocation is not the same as issuer of credential")
	}

	// create correct challenge for verification
	payload := generateRevocationChallenge(r)

	return c.verifyProof(payload, r.Issuer, r.Proof, &r.Date)
}

func generateRevocationChallenge(r credential.Revocation) []byte {
	// without JWS
	proof := r.Proof.Proof

	// payload
	r.Proof = nil
	payload, _ := json.Marshal(r)

	// proof
	prJSON, _ := json.Marshal(proof)

	sums := append(hash.SHA256Sum(prJSON).Slice(), hash.SHA256Sum(payload).Slice()...)
	tbs := base64.RawURLEncoding.EncodeToString(sums)

	return []byte(tbs)
}

