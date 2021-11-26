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

package credential

import (
	"errors"
	"github.com/google/uuid"
	ssi "github.com/ugradid/ugradid-common"
	"github.com/ugradid/ugradid-common/vc"
	"time"
)

// Builder is an abstraction for extending a partial VC into a fully valid VC
type Builder interface {
	// Fill sets the defaults for common fields
	Fill(vc *vc.VerifiableCredential) error
}

// defaultBuilder fills in the type, issuanceDate and context
type schemaCredentialBuilder struct {
	vcType string
}

var nowFunc = time.Now

func FillCredential(credential *vc.VerifiableCredential, vcType string) error {
	credential.Context = []ssi.URI{vc.VCContextV1URI(), *UgraContextURI}

	defaultType := vc.VerifiableCredentialTypeV1URI()
	if !credential.IsType(defaultType) {
		credential.Type = append(credential.Type, defaultType)
	}

	builderType, _ := ssi.ParseURI(vcType)
	if !credential.IsType(*builderType) {
		credential.Type = append(credential.Type, *builderType)
	}

	credential.IssuanceDate = nowFunc()

	id := vc.GenerateCredentialID(credential.Issuer, uuid.New().String())

	credentialId, err := ssi.ParseURI(id)

	if err != nil {
		return errors.New("failed generate credential id")
	}

	credential.ID = credentialId

	return nil
}

func (d schemaCredentialBuilder) Fill(credential *vc.VerifiableCredential) error {
	if err := d.fillCredentialSchema(credential.CredentialSchema); err != nil {
		return err
	}
	return FillCredential(credential, d.vcType)
}

func (d schemaCredentialBuilder) fillCredentialSchema(schema *vc.CredentialSchema) error {
	if schema == nil {
		return errors.New("credential schema is required")
	}
	schema.Type = ssi.JsonSchemaValidator2018
	return nil
}
