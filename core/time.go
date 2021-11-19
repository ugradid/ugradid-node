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

package core

import "time"

// Period is a convenience type for a dateTime range.
type Period struct {
	Begin time.Time  `json:"begin"`
	End   *time.Time `json:"end,omitempty"`
}

// Contains checks if the given time falls within this period. The bounds are inclusive.
func (p Period) Contains(when time.Time) bool {
	if when.Before(p.Begin) {
		return false
	}

	return !(p.End != nil && when.After(*p.End))
}


