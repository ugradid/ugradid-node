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
	"fmt"
	"github.com/google/uuid"
	ssi "github.com/ugradid/ugradid-common"
	"github.com/ugradid/ugradid-common/vc"
	"time"
)

// Builder is an abstraction for extending a partial VC into a fully valid VC
type Builder interface {
	// Fill sets the defaults for common fields
	Fill(vc *vc.VerifiableCredential)
}

// defaultBuilder fills in the type, issuanceDate and context
type defaultBuilder struct {}

var nowFunc = time.Now

func (d defaultBuilder) Fill(credential *vc.VerifiableCredential) {
	credential.Context = []ssi.URI{vc.VCContextV1URI(), *UgraContextURI}

	defaultType := vc.VerifiableCredentialTypeV1URI()
	if !credential.IsType(defaultType) {
		credential.Type = append(credential.Type, defaultType)
	}

	credential.IssuanceDate = nowFunc()
	credential.ID = generateID(credential.Issuer)

	return
}

func generateID(issuer ssi.URI) *ssi.URI {
	id := fmt.Sprintf("%s#%s", issuer.String(), uuid.New().String())
	u, _ := ssi.ParseURI(id)
	return u
}
