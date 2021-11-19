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

package types

import (
	"crypto"
	"github.com/ugradid/ugradid-common"
	"github.com/ugradid/ugradid-common/did"
	ucrypto "github.com/ugradid/ugradid-node/crypto"
	"github.com/ugradid/ugradid-node/crypto/hash"
	"time"
)

// DocIterator is the function type for iterating over the all current DID Documents in the store
type DocIterator func(doc did.Document, metadata DocumentMetadata) error

// DocResolver is the interface that groups all the DID Document read methods
type DocResolver interface {
	// Resolve returns a DID Document for the provided DID.
	// If metadata is not provided the latest version is returned.
	// If metadata is provided then the result is filtered or scoped on that metadata.
	// It returns ErrNotFound if there are no corresponding DID documents or when the DID Documents are disjoint with the provided ResolveMetadata
	// It returns ErrDeactivated if the DID Document has been deactivated
	// It returns ErrNoActiveController if all of the DID Documents controllers have been deactivated
	Resolve(id did.DID, metadata *ResolveMetadata) (*did.Document, *DocumentMetadata, error)
	// ResolveControllers finds the DID Document controllers
	ResolveControllers(input did.Document, metadata *ResolveMetadata) ([]did.Document, error)
}

// DocWriter is the interface that groups al the DID Document write methods
type DocWriter interface {
	// Write writes a DID Document.
	// Returns ErrDIDAlreadyExists when DID already exists
	// When a document already exists, the Update should be used instead
	Write(document did.Document, metadata DocumentMetadata) error
}

// DocUpdater is the interface that defines functions that alter the state of a DID document
type DocUpdater interface {
	// Update replaces the DID document identified by DID with the nextVersion
	// To prevent updating stale data a hash of the current version should be provided.
	// If the given hash does not represents the current version, a ErrUpdateOnOutdatedData is returned
	// If the DID Document is not found, ErrNotFound is returned
	// If the DID Document is not managed by this node, ErrDIDNotManagedByThisNode is returned
	// If the DID Document is not active, ErrDeactivated is returned
	Update(id did.DID, current hash.SHA256Hash, next did.Document, metadata *DocumentMetadata) error
}

// Store is the interface that groups all low level VDR DID storage operations.
type Store interface {
	// Resolve returns the DID Document for the provided DID.
	// If metadata is not provided the latest version is returned.
	// If metadata is provided then the result is filtered or scoped on that metadata.
	// It returns ErrNotFound if there are no corresponding DID documents or when the DID Documents are disjoint with the provided ResolveMetadata
	Resolve(id did.DID, metadata *ResolveMetadata) (*did.Document, *DocumentMetadata, error)
	// Iterate loops over all the latest versions of the stored DID Documents and applies fn.
	// Calling any of the Store's functions from the given fn might cause a deadlock.
	Iterate(fn DocIterator) error

	DocWriter
	DocUpdater
}

// KeyResolver is the interface for resolving keys.
// This can be used for checking if a signing key is valid at a point in time or to just find a valid key for signing.
type KeyResolver interface {
	// ResolveSigningKeyID looks up a signing key of the specified holder. It returns the ID
	// of the found key. Typically used to find a key for signing one's own documents. If no suitable keys
	// are found an error is returned.
	ResolveSigningKeyID(holder did.DID, validAt *time.Time) (string, error)
	// ResolveSigningKey looks up a specific signing key and returns it as crypto.PublicKey. If the key can't be found
	// or isn't meant for signing an error is returned.
	ResolveSigningKey(keyID string, validAt *time.Time) (crypto.PublicKey, error)
	// ResolveAssertionKeyID look for a valid assertion key for the give DID. If multiple keys are valid, the first one is returned.
	// An ErrKeyNotFound is returned when no key is found.
	ResolveAssertionKeyID(id did.DID) (ssi.URI, error)
	// ResolvePublicKeyInTime loads the key from a DID Document
	// It returns ErrKeyNotFound when the key could not be found in the DID Document.
	// It returns ErrNotFound when the DID Document can't be found.
	ResolvePublicKeyInTime(kid string, validAt *time.Time) (crypto.PublicKey, error)
	// ResolvePublicKey loads the key from a DID Document where the DID Document
	// was created with one of the given tx refs
	// It returns ErrKeyNotFound when the key could not be found in the DID Document.
	// It returns ErrNotFound when the DID Document can't be found.
	ResolvePublicKey(kid string, sourceTransactionsRefs []hash.SHA256Hash) (crypto.PublicKey, error)
}

// Vdr defines the public end facing methods for the Verifiable Data Registry.
type Vdr interface {
	DocCreator
	DocUpdater

	// ConflictedDocuments returns the DID Document and metadata of all documents with a conflict.
	ConflictedDocuments() ([]did.Document, []DocumentMetadata, error)
}

// DocCreator is the interface that wraps the Create method
type DocCreator interface {
	// Create creates a new DID document and returns it.
	// The ID in the provided DID document will be ignored and a new one will be generated.
	// If something goes wrong an error is returned.
	// Implementors should generate private key and store it in a secure backend
	Create(options DIDCreationOptions) (*did.Document, ucrypto.Key, error)
}

