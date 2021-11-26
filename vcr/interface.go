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
	"errors"
	ssi "github.com/ugradid/ugradid-common"
	"github.com/ugradid/ugradid-common/vc"
	"github.com/ugradid/ugradid-common/vc/schema"
	"github.com/ugradid/ugradid-node/vcr/credential"
	"time"
)

// ErrInvalidIssuer is returned when a credential is issued by a DID that is unknown or when the private key is missing.
var ErrInvalidIssuer = errors.New("invalid credential issuer")

// ErrInvalidSubject is returned when a credential is issued to a DID that is unknown or revoked.
var ErrInvalidSubject = errors.New("invalid credential subject")

// ErrNotFoundCredential is returned when a credential can not be found based on its ID.
var ErrNotFoundCredential = errors.New("credential not found")

// ErrNotFoundSchema is returned when a schema can not be found based on its ID.
var ErrNotFoundSchema = errors.New("schema not found")

// ErrRevoked is returned when a credential has been revoked and the required action requires it to not be revoked.
var ErrRevoked = errors.New("credential is revoked")

// ErrUntrusted is returned when a credential is resolved or searched but its issuer is not trusted.
var ErrUntrusted = errors.New("credential issuer is untrusted")

// ErrInvalidCredential is returned when validation failed
var ErrInvalidCredential = errors.New("invalid credential")

// ErrInvalidPeriod is returned when the credential is not valid at the given time.
var ErrInvalidPeriod = errors.New("credential not valid at given time")

var vcDocumentType = "application/vc+json"

var revocationDocumentType = "application/vc+json;type=revocation"

var schemaDocumentType = "application/vc+json;type=schema"

// Writer is the interface that groups al the VC write methods
type Writer interface {
	// StoreCredential writes a VC to storage. Before writing, it calls Verify!
	StoreCredential(vc vc.VerifiableCredential) error
	// StoreRevocation writes a revocation to storage.
	StoreRevocation(r credential.Revocation) error
	// StoreSchema writes a credential schema to storage
	StoreSchema(s schema.Schema) error
}

// Reader is the interface that groups al the VC write methods
type Reader interface {
	// GetCredential read a VC from storage
	GetCredential(ID ssi.URI, credentialType string) (vc.VerifiableCredential, error)
	// isRevoked check revoke vc from storage
	isRevoked(ID ssi.URI) (bool, error)
	// GetSchema read a vc schema from storage
	GetSchema(ID ssi.URI) (schema.Schema, error)
}

// Resolver binds all read type of operations into an interface
type Resolver interface {
	// Resolve returns a credential based on its ID.
	// The optional resolveTime will resolve the credential at that point in time.
	// The credential will still be returned to the case of ErrRevoked and ErrUntrusted.
	// For other errors, nil is returned
	Resolve(ID ssi.URI, credentialType string, resolveTime *time.Time) (*vc.VerifiableCredential, error)
}

// Validator is the VCR interface for validation options
type Validator interface {
	// Validate checks if the given credential:
	// - is not revoked
	// - is valid at the given time (or now if not give)
	// - has a valid issuer
	// - has a valid signature if checkSignature is true
	// if allowUntrusted == false, the issuer must also be a trusted DID
	// May return ErrRevoked, ErrUntrusted or ErrInvalidPeriod
	Validate(credential vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error
}

// TrustManager bundles all trust related methods in one interface
type TrustManager interface {
}

// SchemaManager combines all methods for working with schema
type SchemaManager interface {
	// Create new schema and publish
	Create(s schema.Schema) (*schema.Schema, error)
}

// Vcr is the interface that covers all functionality of the vcr store.
type Vcr interface {
	// Issue creates and publishes a new VC.
	// An optional expirationDate can be given.
	// VCs are stored when the network has successfully published them.
	Issue(vcToIssue vc.VerifiableCredential) (*vc.VerifiableCredential, error)
	// Revoke a credential based on its ID, the Issuer will be resolved automatically.
	// The statusDate will be set to the current time.
	// It returns an error if the credential, issuer or private key can not be found.
	Revoke(ID ssi.URI, credentialType string) (*credential.Revocation, error)

	Writer
	Reader
	Resolver
	Validator
	TrustManager
	SchemaManager
}
