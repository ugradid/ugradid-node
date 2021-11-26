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
	"github.com/google/uuid"
	ssi "github.com/ugradid/ugradid-common"
	"github.com/ugradid/ugradid-common/vc/schema"
	"time"
)

var nowFunc = time.Now

const (
	schemaVersion = "1.0"
)

func FillSchema(template *schema.Schema) error  {

	template.Type = *UgraSchemaTypeURI
	template.Version = schemaVersion
	template.Authored = nowFunc()

	id := schema.GenerateSchemaID(template.Author, uuid.New().String(), template.Version)

	schemaId, err := ssi.ParseURI(id)

	if err != nil {
		return errors.New("failed generate credential id")
	}

	template.ID = schemaId

	return nil
}
