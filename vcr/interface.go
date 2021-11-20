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
	"github.com/ugradid/ugradid-node/vcr/credential"
	"time"
)

// ErrInvalidIssuer is returned when a credential is issued by a DID that is unknown or when the private key is missing.
var ErrInvalidIssuer = errors.New("invalid credential issuer")

// ErrInvalidSubject is returned when a credential is issued to a DID that is unknown or revoked.
var ErrInvalidSubject = errors.New("invalid credential subject")

// ErrNotFound is returned when a credential can not be found based on its ID.
var ErrNotFound = errors.New("credential not found")

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

// Writer is the interface that groups al the VC write methods
type Writer interface {
	// StoreCredential writes a VC to storage. Before writing, it calls Verify!
	StoreCredential(vc vc.VerifiableCredential) error
	// StoreRevocation writes a revocation to storage.
	StoreRevocation(r credential.Revocation) error
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
	Resolver
	Validator
}
