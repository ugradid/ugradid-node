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

package schema

import (
	"errors"
	"fmt"
	"github.com/ugradid/ugradid-common/vc/schema"
)

type Validator interface {
	// Validate the given credential schema according to the rules of the schema type
	Validate(sc schema.Schema) error
}

// ErrValidation is a common error indicating validation failed
var ErrValidation = errors.New("schema validation failed")

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

func failure(err string, args ...interface{}) error {
	errStr := fmt.Sprintf(err, args...)
	return &validationError{errStr}
}

func Validate(sc schema.Schema) error {
	if !sc.IsType(*UgraSchemaTypeURI) {
		return failure("type 'UgraSchemaType' is required")
	}

	if err := sc.ValidateID(); err != nil {
		return failure("'id' is required")
	}

	if err := sc.ValidateVersion(); err != nil {
		return failure("'version' is required")
	}

	if len(sc.Name) == 0 {
		return failure("'name' is required")
	}

	if sc.Authored.IsZero() {
		return failure("'authored' is required")
	}

	if sc.Proof == nil {
		return failure("'proof' is required")
	}

	return nil
}

type JsonSchemaValidator struct{}

func (d JsonSchemaValidator) Validate(sc schema.Schema) error {
	if err := schema.ValidateJSONSchema(sc.Schema); err != nil {
		return err
	}
	return Validate(sc)
}
