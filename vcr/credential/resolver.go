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

import "github.com/ugradid/ugradid-common/vc"

// FindValidatorAndBuilder finds the Validator and Builder for the credential Type
// It returns nils when not found.
// It only supports VCs with one additional type next to the default VerifiableCredential type.
func FindValidatorAndBuilder(credential vc.VerifiableCredential) (Validator, Builder) {
	if vcTypes := ExtractTypes(credential); len(vcTypes) > 0 {
		return defaultCredentialValidator{}, defaultBuilder{}
	}
	return nil, nil
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