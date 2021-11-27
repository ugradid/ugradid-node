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
	ssi "github.com/ugradid/ugradid-common"
	"github.com/ugradid/ugradid-common/vc"
	"github.com/ugradid/ugradid-common/vc/schema"
	eibb "github.com/ugradid/ugradid-eibb"
	"github.com/ugradid/ugradid-node/vcr/concept"
	"github.com/ugradid/ugradid-node/vcr/credential"
	"github.com/ugradid/ugradid-node/vcr/log"
	"time"
)

const revocationCollection = "revocation"

const schemaCollection = "schema"

// StoreCredential store vc document
func (c *vcr) StoreCredential(credential vc.VerifiableCredential, validAt *time.Time) error {
	if err := c.Verify(credential, validAt); err != nil {
		return err
	}
	return c.writeCredential(credential)
}

// GetCredential find only returns a VC from storage, it does not tell anything about validity
func (c *vcr) GetCredential(ID ssi.URI, credentialType string) (vc.VerifiableCredential, error) {
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

	return credential, ErrNotFoundCredential
}

func (c *vcr) writeCredential(subject vc.VerifiableCredential) error {

	writer, err := credential.FindWriter(subject)

	if err != nil {
		return err
	}

	log.Logger().Tracef("%+v", subject)

	docJson, err := json.Marshal(subject)

	if err != nil {
		return err
	}

	vcType, err := writer.Resolve(subject)

	document := eibb.DocumentFromBytes(docJson)
	var errColl error

	log.Logger().Debugf("Writing type '%s' to vcr store", vcType)

	collection := c.store.Collection(vcType)

	if errColl = collection.Add([]eibb.Document{document}); err != nil {
		return errColl
	}

	return nil
}

// StoreSchema store schema document
func (c *vcr) StoreSchema(sc schema.Schema) error {
	if err := c.verifySchema(sc); err != nil {
		return err
	}
	return c.writeSchema(sc)
}

func (c *vcr) GetSchema(ID ssi.URI) (schema.Schema, error) {
	sc := schema.Schema{}

	qp := eibb.Eq(concept.IDField, ID.String())
	q := eibb.New(qp)

	docs, err := c.store.Collection(schemaCollection).Find(q)

	if err != nil {
		return sc, err
	}
	if len(docs) > 0 {
		// there can be only one
		err = json.Unmarshal(docs[0].Bytes(), &sc)
		if err != nil {
			return sc, errors.Wrap(err, "unable to parse credential from db")
		}

		return sc, nil
	}

	return sc, ErrNotFoundSchema
}

func (c *vcr) writeSchema(sc schema.Schema) error {

	collection := c.store.Collection(schemaCollection)

	doc, err := json.Marshal(sc)

	if err != nil {
		return err
	}

	return collection.Add([]eibb.Document{eibb.DocumentFromBytes(doc)})
}

func (c *vcr) schemaCollection() eibb.Collection {
	return c.store.Collection(schemaCollection)
}

// StoreRevocation store revocation document
func (c *vcr) StoreRevocation(r credential.Revocation) error {
	if err := c.verifyRevocation(r); err != nil {
		return err
	}
	return c.writeRevocation(r)
}

func (c *vcr) writeRevocation(r credential.Revocation) error {
	collection := c.revocationCollection()

	doc, err := json.Marshal(r)

	if err != nil {
		return err
	}

	return collection.Add([]eibb.Document{eibb.DocumentFromBytes(doc)})
}

func (c *vcr) isRevoked(ID ssi.URI) (bool, error) {
	qp := eibb.Eq(concept.SubjectField, ID.String())
	q := eibb.New(qp)

	collection := c.revocationCollection()

	docs, err := collection.Find(q)
	if err != nil {
		return false, err
	}

	if len(docs) >= 1 {
		return true, nil
	}

	return false, nil
}

func (c *vcr) revocationCollection() eibb.Collection {
	return c.store.Collection(revocationCollection)
}
