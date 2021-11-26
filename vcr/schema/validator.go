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
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ugradid/ugradid-common/vc/schema"
	"github.com/ugradid/ugradid-node/vcr/log"
	"github.com/xeipuuv/gojsonschema"
	"strings"
)

var (
	//go:embed assets/draft07.json
	draft07 string
)

// ErrValidation is a common error indicating validation failed
var ErrValidation = errors.New("schema validation failed")

type validationError struct {
	Errors []string
}

func (err validationError) Error() string {
	return fmt.Sprintf("invalid schema: %s", strings.Join(err.Errors, ", "))
}

// Is checks if validationError matches the target error
func (err *validationError) Is(target error) bool {
	return errors.Is(target, ErrValidation)
}

func failure(err string, args ...interface{}) error {
	errStr := fmt.Sprintf(err, args...)
	return &validationError{Errors: []string{errStr}}
}

// ValidateJsonSchema exists to hide gojsonschema logic within this file
// it is the entry-point to validation logic, requiring the caller pass in valid json strings for each argument
func ValidateJsonSchema(schema, document string) error {
	if !IsJSON(schema) {
		return failure("schema is not valid json: %s", schema)
	} else if !IsJSON(document) {
		return failure("document is not valid json: %s", document)
	}
	return ValidateWithJSONLoader(gojsonschema.NewStringLoader(schema), gojsonschema.NewStringLoader(document))
}

// ValidateWithJSONLoader takes schema and document loaders; the document from the loader is validated against
// the schema from the loader. Nil if good, error if bad
func ValidateWithJSONLoader(schemaLoader, documentLoader gojsonschema.JSONLoader) error {
	// Add custom validator(s) and then ValidateWithJSONLoader
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return err
	}

	if !result.Valid() {
		// Accumulate errs
		var errs []string
		for _, err := range result.Errors() {
			errs = append(errs, err.String())
		}
		return validationError{Errors: errs}
	}
	return nil
}

// IsJSON True if string is valid JSON, false otherwise
func IsJSON(str string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(str), &js) == nil
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

func ValidateSchema(sc schema.Schema) error {
	data, err := json.Marshal(sc.Schema)
	if err != nil {
		return err
	}
	log.Logger().Tracef("%+v", data)

	if err := ValidateJsonSchema(draft07, string(data)); err != nil {
		return err
	}
	return Validate(sc)
}
