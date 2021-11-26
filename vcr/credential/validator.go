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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ugradid/ugradid-common/vc"
	"github.com/ugradid/ugradid-common/vc/schema"
	"github.com/ugradid/ugradid-node/network/log"
	schema2 "github.com/ugradid/ugradid-node/vcr/schema"
)

// Validator is the interface specific VC verification.
// Every VC will have its own rules of verification.
type Validator interface {
	// Validate the given credential according to the rules of the VC type.
	Validate(credential vc.VerifiableCredential) error
}

// ErrValidation is a common error indicating validation failed
var ErrValidation = errors.New("credential validation failed")

type validationError struct {
	msg string
}

// Error returns the error message
func (err *validationError) Error() string {
	return fmt.Sprintf("validation failed: %s", err.msg)
}

// Is checks if validationError matches the target error
func (err *validationError) Is(target error) bool {
	return errors.Is(target, ErrValidation)
}

func failureValidate(err string, args ...interface{}) error {
	errStr := fmt.Sprintf(err, args...)
	return &validationError{errStr}
}

// Validate the default fields
func Validate(credential vc.VerifiableCredential) error {
	if !credential.IsType(vc.VerifiableCredentialTypeV1URI()) {
		return failureValidate("type 'VerifiableCredential' is required")
	}

	if !credential.ContainsContext(vc.VCContextV1URI()) {
		return failureValidate("default context is required")
	}

	if !credential.ContainsContext(*UgraContextURI) {
		return failureValidate("ugra context is required")
	}

	if credential.ID == nil {
		return failureValidate("'ID' is required")
	}

	if credential.IssuanceDate.IsZero() {
		return failureValidate("'issuanceDate' is required")
	}

	if credential.Proof == nil {
		return failureValidate("'proof' is required")
	}

	return nil
}

type schemaCredentialValidator struct {
}

func (d schemaCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	if credential.CredentialSchema == nil {
		return failureValidate("credential schema is required")
	}
	return Validate(credential)
}

// ValidateCredential a credential's data is valid against its schema
func ValidateCredential(credentialSubjectSchema schema.Schema, cred vc.VerifiableCredential) error {

	credentialSubjectSchemaJSONBytes, err := json.Marshal(credentialSubjectSchema.Schema)
	if err != nil {
		return err
	}
	credentialSubjectSchemaJSON := string(credentialSubjectSchemaJSONBytes)

	log.Logger().Tracef("%+v", credentialSubjectSchemaJSON)

	credentialSubjectJSONBytes, err := json.Marshal(cred.CredentialSubject)
	if err != nil {
		return err
	}
	credentialSubjectJSON := string(credentialSubjectJSONBytes)

	log.Logger().Tracef("%+v", credentialSubjectJSON)

	// Validate against the credential subject s
	return schema2.ValidateJsonSchema(credentialSubjectSchemaJSON, credentialSubjectJSON)
}
