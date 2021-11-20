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
	"github.com/ugradid/ugradid-common/vc"
	eibb "github.com/ugradid/ugradid-eibb"
	"github.com/ugradid/ugradid-node/vcr/credential"
	"github.com/ugradid/ugradid-node/vcr/log"
)

const revocationCollection = "_revocation"

func (c *vcr) StoreCredential(credential vc.VerifiableCredential) error {
	if err := c.Verify(credential, nil); err != nil {
		return err
	}
	return c.writeCredential(credential)
}

func (c *vcr) writeCredential(subject vc.VerifiableCredential) error {

	vcTypes := credential.ExtractTypes(subject)

	log.Logger().Tracef("%+v", subject)

	docJson, _ := json.Marshal(subject)
	document := eibb.DocumentFromBytes(docJson)
	var err error

	for _, vcType := range vcTypes {
		log.Logger().Debugf("Writing %s to vcr store", vcType)

		collection := c.store.Collection(vcType)
		if err = collection.Add([]eibb.Document{document}); err != nil {
			return err
		}
	}

	return nil
}

func (c *vcr) StoreRevocation(r credential.Revocation) error {
	// verify first
	if err := c.verifyRevocation(r); err != nil {
		return err
	}

	return c.writeRevocation(r)
}

func (c *vcr) writeRevocation(r credential.Revocation) error {
	collection := c.revocationIndex()

	doc, _ := json.Marshal(r)

	return collection.Add([]eibb.Document{eibb.DocumentFromBytes(doc)})
}

func (c *vcr) revocationIndex() eibb.Collection {
	return c.store.Collection(revocationCollection)
}


