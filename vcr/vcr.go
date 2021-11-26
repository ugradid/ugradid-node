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
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	ssi "github.com/ugradid/ugradid-common"
	"github.com/ugradid/ugradid-common/did"
	"github.com/ugradid/ugradid-common/vc"
	eibb "github.com/ugradid/ugradid-eibb"
	"github.com/ugradid/ugradid-node/core"
	"github.com/ugradid/ugradid-node/crypto"
	"github.com/ugradid/ugradid-node/crypto/hash"
	"github.com/ugradid/ugradid-node/network"
	"github.com/ugradid/ugradid-node/vcr/credential"
	"github.com/ugradid/ugradid-node/vcr/log"
	"github.com/ugradid/ugradid-node/vcr/trust"
	doc2 "github.com/ugradid/ugradid-node/vdr/doc"
	vdr "github.com/ugradid/ugradid-node/vdr/types"
	"path"
	"strings"
	"time"
)

// noSync is used to disable bbolt syncing on go-leia during tests
var noSync bool

var timeFunc = time.Now

const maxSkew = 5 * time.Second

type vcr struct {
	config      Config
	store       eibb.Store
	keyStore    crypto.KeyStore
	docResolver vdr.DocResolver
	keyResolver vdr.KeyResolver
	ambassador  Ambassador
	network     network.Transactions
	trustConfig *trust.Config
}

// NewVCRInstance creates a new vcr instance with default config and empty concept registry
func NewVCRInstance(keyStore crypto.KeyStore, docResolver vdr.DocResolver,
	keyResolver vdr.KeyResolver, network network.Transactions) Vcr {

	r := &vcr{
		config:      DefaultConfig(),
		docResolver: docResolver,
		keyStore:    keyStore,
		keyResolver: keyResolver,
		network:     network,
	}

	r.ambassador = NewAmbassador(network, r)

	return r
}

func (c *vcr) Configure(config core.ServerConfig) error {
	var err error

	fsPath := path.Join(config.Datadir, "vcr", c.config.File)
	tcPath := path.Join(config.Datadir, "vcr", c.config.TrustedFile)

	// load trusted issuers
	c.trustConfig = trust.NewConfig(tcPath)

	if err = c.trustConfig.Load(); err != nil {
		return err
	}

	// setup DB connection
	if c.store, err = eibb.NewStore(fsPath, noSync); err != nil {
		return err
	}

	// start listening for new credentials
	c.ambassador.Configure()

	return nil
}

func (c *vcr) Name() string {
	return moduleName
}

func (c *vcr) Config() interface{} {
	return &c.config
}

func (c *vcr) Verify(subject vc.VerifiableCredential, at *time.Time) error {
	// it must have valid content
	validator, _, err := credential.FindValidatorAndBuilder(subject)
	if err != nil {
		return err
	}

	if err := validator.Validate(subject); err != nil {
		return err
	}

	// create correct challenge for verification
	payload, err := generateCredentialChallenge(subject)
	if err != nil {
		return fmt.Errorf("cannot generate challenge: %w", err)
	}

	// extract proof, can't fail already done in generateCredentialChallenge
	var proofs = make([]vc.JSONWebSignature2020Proof, 0)
	_ = subject.UnmarshalProofValue(&proofs)

	proof := &proofs[0]

	if err = c.verifyProof(payload, subject.Issuer, proof, at); err != nil {
		return err
	}

	// next check trusted/period and revocation
	return c.validate(subject, at)
}

func (c *vcr) verifyProof(payload []byte, issuer ssi.URI,
	proof *vc.JSONWebSignature2020Proof, at *time.Time) error {

	// extract proof, can't fail, already done in generateRevocationChallenge
	splittedJws := strings.Split(proof.Jws, "..")
	if len(splittedJws) != 2 {
		return errors.New("invalid 'jws' value in proof")
	}
	sig, err := base64.RawURLEncoding.DecodeString(splittedJws[1])
	if err != nil {
		return err
	}

	// check if key is of issuer
	vm := proof.VerificationMethod
	vm.Fragment = ""
	if vm != issuer {
		return errors.New("verification method is not of issuer")
	}

	// find key
	pk, err := c.keyResolver.ResolveSigningKey(proof.VerificationMethod.String(), at)
	if err != nil {
		return err
	}

	// the proof must be correct
	verifier, _ := jws.NewVerifier(jwa.ES256)
	// the jws lib can't do this for us, so we concat hdr with payload for verification
	challenge := fmt.Sprintf("%s.%s", splittedJws[0], payload)
	if err = verifier.Verify([]byte(challenge), sig, pk); err != nil {
		return err
	}

	return nil
}

func (c *vcr) validate(credential vc.VerifiableCredential, validAt *time.Time) error {
	at := timeFunc()
	if validAt != nil {
		at = *validAt
	}

	issuer, err := did.ParseDIDURL(credential.Issuer.String())
	if err != nil {
		return err
	}

	if credential.IssuanceDate.After(at.Add(maxSkew)) {
		return ErrInvalidPeriod
	}

	if credential.ExpirationDate != nil && credential.ExpirationDate.Add(maxSkew).Before(at) {
		return ErrInvalidPeriod
	}

	_, _, err = c.docResolver.Resolve(*issuer, &vdr.ResolveMetadata{ResolveTime: &at})
	return err
}

func (c *vcr) Issue(template vc.VerifiableCredential) (*vc.VerifiableCredential, error) {

	if len(template.Type) != 1 {
		return nil, errors.New("can only issue credential with 1 type")
	}

	validator, builder, err := credential.FindValidatorAndBuilder(template)

	if err != nil {
		return nil, err
	}

	cred := vc.VerifiableCredential{
		Type:              template.Type,
		CredentialSubject: template.CredentialSubject,
		Issuer:            template.Issuer,
		ExpirationDate:    template.ExpirationDate,
		CredentialSchema:  template.CredentialSchema,
	}

	// find issuer
	issuer, err := did.ParseDID(cred.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer: %w", err)
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
	if err := builder.Fill(&cred); err != nil {
		return nil, fmt.Errorf("failed fill credential: %w", err)
	}

	// sign
	if err := c.generateProof(&cred, kid, key); err != nil {
		return nil, fmt.Errorf("failed to generate credential proof: %w", err)
	}

	// do same validation as network nodes
	if err := validator.Validate(cred); err != nil {
		return nil, err
	}

	if cred.CredentialSchema != nil {
		sc, err := c.GetSchema(cred.CredentialSchema.ID)

		if err != nil {
			return nil, fmt.Errorf("credential subject: %s", err)
		}

		if err := credential.ValidateCredential(sc, cred); err != nil {
			return nil, fmt.Errorf("credential subject is not valid schema: %s", err)
		}
	}

	payload, _ := json.Marshal(cred)

	_, err = c.network.CreateTransaction(
		vcDocumentType, payload, key, false, cred.IssuanceDate, meta.SourceTransactions)

	if err != nil {
		return nil, fmt.Errorf("failed to publish credential: %w", err)
	}

	log.Logger().Infof(
		"Verifiable Credential issued (id=%s,type=%s)", cred.ID, template.Type)

	return &cred, nil
}

func (c *vcr) Resolve(ID ssi.URI, credentialType string, resolveTime *time.Time) (*vc.VerifiableCredential, error) {

	credential, err := c.GetCredential(ID, credentialType)
	if err != nil {
		return nil, err
	}

	// we don't have to check the signature, it's coming from our own store.
	if err = c.Validate(credential, false, false, resolveTime); err != nil {
		switch err {
		case ErrRevoked:
			return &credential, ErrRevoked
		case ErrUntrusted:
			return &credential, ErrUntrusted
		default:
			return nil, err
		}
	}
	return &credential, nil
}

func (c *vcr) Validate(credential vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error {

	revoked, err := c.isRevoked(*credential.ID)
	if revoked {
		return ErrRevoked
	}
	if err != nil {
		return err
	}

	if !allowUntrusted {
		trusted := c.isTrusted(credential)
		if !trusted {
			return ErrUntrusted
		}
	}

	if checkSignature {
		return c.Verify(credential, validAt)
	}
	return c.validate(credential, validAt)
}

func (c *vcr) isTrusted(credential vc.VerifiableCredential) bool {
	for _, t := range credential.Type {
		if c.trustConfig.IsTrusted(t, credential.Issuer) {
			return true
		}
	}

	return false
}

func (c *vcr) generateProof(credential *vc.VerifiableCredential, kid ssi.URI, key crypto.Key) error {
	// create proof
	pr := vc.Proof{
		Type:               "JsonWebSignature2020",
		ProofPurpose:       "assertionMethod",
		VerificationMethod: kid,
		Created:            credential.IssuanceDate,
	}
	credential.Proof = []interface{}{pr}

	// create correct signing challenge
	challenge, err := generateCredentialChallenge(*credential)
	if err != nil {
		return err
	}

	sig, err := crypto.SignJWS(challenge, detachedJWSHeaders(), key.Signer())
	if err != nil {
		return err
	}

	// remove payload from sig since a detached jws is required.
	dsig := toDetachedSignature(sig)

	credential.Proof = []interface{}{
		vc.JSONWebSignature2020Proof{
			Proof: pr,
			Jws:   dsig,
		},
	}

	return nil
}

func generateCredentialChallenge(credential vc.VerifiableCredential) ([]byte, error) {
	var proofs = make([]vc.JSONWebSignature2020Proof, 1)

	if err := credential.UnmarshalProofValue(&proofs); err != nil {
		return nil, err
	}

	if len(proofs) != 1 {
		return nil, errors.New("expected a single Proof for challenge generation")
	}

	// payload
	credential.Proof = nil
	payload, _ := json.Marshal(credential)

	// proof
	proof := proofs[0]
	proof.Jws = ""
	prJSON, _ := json.Marshal(proof)

	sums := append(hash.SHA256Sum(prJSON).Slice(), hash.SHA256Sum(payload).Slice()...)
	tbs := base64.RawURLEncoding.EncodeToString(sums)

	return []byte(tbs), nil
}

// detachedJWSHeaders creates headers for JsonWebSignature2020
// the alg will be based upon the key
// {"b64":false,"crit":["b64"]}
func detachedJWSHeaders() map[string]interface{} {
	return map[string]interface{}{
		"b64":  false,
		"crit": []string{"b64"},
	}
}

// toDetachedSignature removes the middle part of the signature
func toDetachedSignature(sig string) string {
	splitted := strings.Split(sig, ".")
	return strings.Join([]string{splitted[0], splitted[2]}, "..")
}
