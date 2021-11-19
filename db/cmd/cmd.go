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
	"github.com/ugradid/ugradid-node/db"
)

// ConfigFile is used as --database.file config flag
const ConfigFile string = "database.file"

// FlagSet returns the configuration flags for database
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("database", pflag.ContinueOnError)

	defs := db.DefaultDatabaseConfig()
	flags.String(ConfigFile, defs.File,
		fmt.Sprintf("File name to use for database system, default: %s", defs.File))

	return flags
}
