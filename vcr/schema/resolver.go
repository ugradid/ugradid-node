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
	"fmt"
	"github.com/ugradid/ugradid-common/vc/schema"
)

func FindValidator(sc schema.JsonSchema) (Validator, error) {
	switch sc.SchemaRef {
	case schema.Draft7Schema:
		return JsonSchemaValidator{}, nil
	default:
		return nil, fmt.Errorf("schema '%s' is not supported", sc.SchemaRef)
	}
}
