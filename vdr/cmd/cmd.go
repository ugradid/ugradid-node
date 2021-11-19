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

package cmd

import (
	"fmt"
	"github.com/spf13/pflag"
	"github.com/ugradid/ugradid-node/vdr/store"
)

// ConfigFile is used as --vdr.store.file config flag
const ConfigFile string = "vdr.store.file"

// FlagSet contains flags relevant for the VDR instance
func FlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("vdr", pflag.ContinueOnError)

	defs := store.DefaultVdrStoreConfig()
	flagSet.String(ConfigFile, defs.File,
		fmt.Sprintf("File name to use for vdr store, default: %s", defs.File))

	return flagSet
}
