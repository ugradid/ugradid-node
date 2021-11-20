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
	"github.com/ugradid/ugradid-node/vcr/concept"
	"github.com/ugradid/ugradid-node/vcr/credential"
	"github.com/ugradid/ugradid-node/vcr/log"
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

	// store strictMode
	c.config = Config{strictMode: config.Strictmode}

	fsPath := path.Join(config.Datadir, "vcr", "credentials.db")

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
	validator, _ := credential.FindValidatorAndBuilder(subject)
	if validator == nil {
		return errors.New("unknown credential type")
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
	proof := proofs[0]
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
	if vm != subject.Issuer {
		return errors.New("verification method is not of issuer")
	}

	// find key
	pk, err := c.keyResolver.ResolveSigningKey(proof.VerificationMethod.String(), at)
	if err != nil {
		return err
	}

	// the proof must be correct
	alg, err := crypto.SignatureAlgorithm(pk)
	if err != nil {
		return err
	}

	verifier, _ := jws.NewVerifier(alg)
	// the jws lib can't do this for us, so we concat hdr with payload for verification
	challenge := fmt.Sprintf("%s.%s", splittedJws[0], payload)
	if err = verifier.Verify([]byte(challenge), sig, pk); err != nil {
		return err
	}

	// next check trusted/period and revocation
	return c.validate(subject, at)
}

func (c *vcr) Revoke(ID ssi.URI, credentialType string) (*credential.Revocation, error) {
	// first find it using a query on id.
	target, err := c.find(ID, credentialType)
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

func (c *vcr) isRevoked(ID ssi.URI) (bool, error) {
	qp := eibb.Eq(concept.SubjectField, ID.String())
	q := eibb.New(qp)

	gIndex := c.revocationIndex()
	docs, err := gIndex.Find(q)
	if err != nil {
		return false, err
	}

	if len(docs) >= 1 {
		return true, nil
	}

	return false, nil
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

	// extract proof, can't fail, already done in generateRevocationChallenge
	splittedJws := strings.Split(r.Proof.Jws, "..")
	if len(splittedJws) != 2 {
		return errors.New("invalid 'jws' value in proof")
	}
	sig, err := base64.RawURLEncoding.DecodeString(splittedJws[1])
	if err != nil {
		return err
	}

	// check if key is of issuer
	vm := r.Proof.VerificationMethod
	vm.Fragment = ""
	if vm != r.Issuer {
		return errors.New("verification method is not of issuer")
	}

	// find key
	pk, err := c.keyResolver.ResolveSigningKey(r.Proof.VerificationMethod.String(), &r.Date)
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

func (c *vcr) Issue(template vc.VerifiableCredential) (*vc.VerifiableCredential, error) {

	if len(template.Type) != 1 {
		return nil, errors.New("can only issue credential with 1 type")
	}

	validator, builder := credential.FindValidatorAndBuilder(template)

	credential := vc.VerifiableCredential{
		Type:              template.Type,
		CredentialSubject: template.CredentialSubject,
		Issuer:            template.Issuer,
		ExpirationDate:    template.ExpirationDate,
	}

	// find issuer
	issuer, err := did.ParseDID(credential.Issuer.String())
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
	builder.Fill(&credential)

	// sign
	if err := c.generateProof(&credential, kid, key); err != nil {
		return nil, fmt.Errorf("failed to generate credential proof: %w", err)
	}

	// do same validation as network nodes
	if err := validator.Validate(credential); err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(credential)

	_, err = c.network.CreateTransaction(
		vcDocumentType, payload, key, false, credential.IssuanceDate, meta.SourceTransactions)

	if err != nil {
		return nil, fmt.Errorf("failed to publish credential: %w", err)
	}

	log.Logger().Infof(
		"Verifiable Credential issued (id=%s,type=%s)", credential.ID, template.Type)

	return &credential, nil
}

func (c *vcr) Resolve(ID ssi.URI, credentialType string, resolveTime *time.Time) (*vc.VerifiableCredential, error) {

	credential, err := c.find(ID, credentialType)
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

	if checkSignature {
		return c.Verify(credential, validAt)
	}
	return c.validate(credential, validAt)
}

// find only returns a VC from storage, it does not tell anything about validity
func (c *vcr) find(ID ssi.URI, credentialType string) (vc.VerifiableCredential, error) {
	credential := vc.VerifiableCredential{}

	qp := eibb.Eq(concept.IDField, ID.String())
	q := eibb.New(qp)

	docs, err := c.store.Collection(credentialType).Find(q)
	if err != nil {
		return credential, err
	}
	if len(docs) > 0 {
		// there can be only one
		err = json.Unmarshal(docs[0].Bytes(), &credential)
		if err != nil {
			return credential, errors.Wrap(err, "unable to parse credential from db")
		}

		return credential, nil
	}

	return credential, ErrNotFound
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
