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

package vdr

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/ugradid/ugradid-common/did"
	"github.com/ugradid/ugradid-node/core"
	"github.com/ugradid/ugradid-node/crypto"
	"github.com/ugradid/ugradid-node/crypto/hash"
	"github.com/ugradid/ugradid-node/network"
	"github.com/ugradid/ugradid-node/vdr/doc"
	"github.com/ugradid/ugradid-node/vdr/log"
	"github.com/ugradid/ugradid-node/vdr/store"
	"github.com/ugradid/ugradid-node/vdr/types"
	"time"
)

// Vdr stands for the Nuts Verifiable Data Registry. It is the public entrypoint to work with W3C DID documents.
// It connects the Resolve, Create and Update DID methods to the network, and receives events back from the network which are processed in the store.
// It is also a Runnable, Diagnosable and Configurable Nuts Engine.
type Vdr struct {
	config            Config
	store             types.Store
	network           network.Transactions
	OnChange          func(registry *Vdr)
	_logger           *logrus.Entry
	didDocCreator     types.DocCreator
	didDocResolver    types.DocResolver
	keyStore          crypto.KeyStore
}

// NewVdr creates a new VDR with provided params
func NewVdr(config Config, cryptoClient crypto.KeyStore,
	networkClient network.Transactions, store types.Store) *Vdr {
	return &Vdr{
		config:            config,
		network:           networkClient,
		_logger:           log.Logger(),
		store:             store,
		didDocCreator:     doc.Creator{KeyStore: cryptoClient},
		didDocResolver:    doc.Resolver{Store: store},
		keyStore:          cryptoClient,
	}
}

func (r *Vdr) Name() string {
	return moduleName
}

func (r *Vdr) Config() interface{} {
	return &r.config
}

// Configure configures the VDR engine.
func (r *Vdr) Configure(_ core.ServerConfig) error {
	// Initiate the routines for auto-updating the data.
	return nil
}

func (r *Vdr) ConflictedDocuments() ([]did.Document, []types.DocumentMetadata, error) {
	conflictedDocs := make([]did.Document, 0)
	conflictedMeta := make([]types.DocumentMetadata, 0)

	err := r.store.Iterate(func(doc did.Document, metadata types.DocumentMetadata) error {
		if metadata.IsConflicted() {
			conflictedDocs = append(conflictedDocs, doc)
			conflictedMeta = append(conflictedMeta, metadata)
		}
		return nil
	})
	return conflictedDocs, conflictedMeta, err
}

// Create generates a new DID Document
func (r *Vdr) Create(options types.DIDCreationOptions) (*did.Document, crypto.Key, error) {
	log.Logger().Debug("Creating new DID Document.")
	document, key, err := r.didDocCreator.Create(options)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create DID document: %w", err)
	}

	payload, err := json.Marshal(document)
	if err != nil {
		return nil, nil, err
	}

	_, err = r.network.CreateTransaction(didDocumentType, payload, key, true, time.Now(), []hash.SHA256Hash{})
	if err != nil {
		return nil, nil, fmt.Errorf("could not store DID document in network: %w", err)
	}

	log.Logger().Infof("New DID Document created (DID=%s)", document.ID)

	return document, key, nil
}

// Update updates a DID Document based on the DID and current hash
func (r *Vdr) Update(id did.DID, current hash.SHA256Hash, next did.Document, _ *types.DocumentMetadata) error {
	log.Logger().Debugf("Updating DID Document (DID=%s)", id)
	resolverMetadata := &types.ResolveMetadata{
		Hash:             &current,
		AllowDeactivated: true,
	}
	currentDIDDocument, currentMeta, err := r.store.Resolve(id, resolverMetadata)
	if err != nil {
		return err
	}
	if store.IsDeactivated(*currentDIDDocument) {
		return types.ErrDeactivated
	}

	if err = CreateDocumentValidator().Validate(next); err != nil {
		return err
	}

	payload, err := json.Marshal(next)
	if err != nil {
		return err
	}

	controller, key, err := r.resolveControllerWithKey(*currentDIDDocument)
	if err != nil {
		return err
	}

	// for the metadata
	_, controllerMeta, err := r.didDocResolver.Resolve(controller.ID, nil)
	if err != nil {
		return err
	}

	// a DIDDocument update must point to its previous version, current heads and the controller TX (for signing key transaction ordering)
	previousTransactions := append(currentMeta.SourceTransactions, controllerMeta.SourceTransactions...)

	_, err = r.network.CreateTransaction(didDocumentType, payload, key, false, time.Now(), previousTransactions)
	if err == nil {
		log.Logger().Infof("DID Document updated (DID=%s)", id)
	} else {
		log.Logger().WithError(err).Warn("Unable to update DID document")
		if errors.Is(err, crypto.ErrKeyNotFound) {
			return types.ErrDIDNotManagedByThisNode
		}
	}

	return err
}

func (r *Vdr) resolveControllerWithKey(doc did.Document) (did.Document, crypto.Key, error) {
	controllers, err := r.didDocResolver.ResolveControllers(doc, nil)
	if err != nil {
		return did.Document{}, nil, fmt.Errorf("error while finding controllers for document: %w", err)
	}
	if len(controllers) == 0 {
		return did.Document{}, nil, fmt.Errorf("could not find any controllers for document")
	}

	var key crypto.Key
	for _, c := range controllers {
		for _, cik := range c.CapabilityInvocation {
			key, err = r.keyStore.Resolve(cik.ID.String())
			if err == nil {
				return c, key, nil
			}
		}
	}

	if errors.Is(err, crypto.ErrKeyNotFound) {
		return did.Document{}, nil, types.ErrDIDNotManagedByThisNode
	}

	return did.Document{}, nil, fmt.Errorf("could not find capabilityInvocation key for updating the DID document: %w", err)
}