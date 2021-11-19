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

import ssi "github.com/ugradid/ugradid-common"

const (
	// UgraContext is the ugra specific json-ld context
	UgraContext = "https://ugradid.ru/credentials/v1"
)

var (
	// UgraContextURI is the  specific json-ld context as URI
	UgraContextURI, _ = ssi.ParseURI(UgraContext)
)

