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

package v1

import (
	"github.com/ugradid/ugradid-common/vc"
	"github.com/ugradid/ugradid-common/vc/schema"
)

// VerifiableCredential is an alias to use from within the API
type VerifiableCredential = vc.VerifiableCredential

// CredentialSubject is an alias to use from within the API
type CredentialSubject = interface{}

// IssueVCRequest is an alias to use from within the API for issuing VCs.
type IssueVCRequest = vc.VerifiableCredential

// CreateSchemaRequest isa an alias
type CreateSchemaRequest = schema.Schema

// Schema isa an alias
type Schema = schema.Schema
