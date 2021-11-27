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
	"fmt"
	"github.com/ugradid/ugradid-common/vc"
)

// ErrResolveCredential is a common error indicating validation failed
var ErrResolveCredential = errors.New("credential resolve failed")

type resolveError struct {
	msg string
}

// Error returns the error message
func (err *resolveError) Error() string {
	return fmt.Sprintf("resolve failed: %s", err.msg)
}

// Is checks if validationError matches the target error
func (err *resolveError) Is(target error) bool {
	return errors.Is(target, ErrValidation)
}

func failureResolve(err string, args ...interface{}) error {
	errStr := fmt.Sprintf(err, args...)
	return &resolveError{errStr}
}

// FindValidatorAndBuilder finds the Validator and Builder for the credential Type
func FindValidatorAndBuilder(credential vc.VerifiableCredential) (Validator, Builder, error) {
	if vcTypes := ExtractTypes(credential); len(vcTypes) > 0 {
		for _, t := range vcTypes {
			switch t {
			case vc.SchemaCredentialType:
				return schemaCredentialValidator{}, schemaCredentialBuilder{vcType: t}, nil
			default:
				return nil, nil, failureResolve("credential type '%s' is not supported", t)
			}
		}
	}
	return nil, nil, failureResolve("credential type is required")
}

// FindWriter finds the Writer for the credential Type
func FindWriter(credential vc.VerifiableCredential) (Writer, error) {
	if vcTypes := ExtractTypes(credential); len(vcTypes) > 0 {
		for _, t := range vcTypes {
			switch t {
			case vc.SchemaCredentialType:
				return schemaWriterCredential{}, nil
			default:
				return nil, failureResolve("credential type '%s' is not supported", t)
			}
		}
	}
	return nil, failureResolve("credential type is required")
}

// ExtractTypes extract additional VC types from the VC as strings
func ExtractTypes(credential vc.VerifiableCredential) []string {
	var vcTypes []string

	for _, t := range credential.Type {
		if t != vc.VerifiableCredentialTypeV1URI() {
			vcTypes = append(vcTypes, t.String())
		}
	}

	return vcTypes
}
