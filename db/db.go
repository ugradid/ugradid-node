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

package db

import (
	"errors"
	"github.com/sirupsen/logrus"
	"github.com/ugradid/ugradid-node/core"
	"go.etcd.io/bbolt"
	"os"
	"path"
	"path/filepath"
)

// boltDBFileMode holds the Unix file mode the created BBolt database files will have.
const boltDBFileMode = 0600

// defaultBBoltOptions are given to bbolt, allows for package local adjustments during test
var defaultBBoltOptions = bbolt.DefaultOptions

const (
	// ModuleName contains the name of this module
	ModuleName = "database"
)

// Config holds the values for the database engine
type Config struct {
	File string `koanf:"database.file"`
}

// DefaultDatabaseConfig returns a Config with sane defaults
func DefaultDatabaseConfig() Config {
	return Config{
		File: "ugradid.db",
	}
}

// Database holds references to database and needed config
type Database struct {
	*bbolt.DB
	config Config
}

// NewDatabaseInstance creates a new instance of the database engine.
func NewDatabaseInstance() *Database {
	return &Database{
		config: DefaultDatabaseConfig(),
	}
}

func (db *Database) Name() string {
	return ModuleName
}

func (db *Database) Config() interface{} {
	return &db.config
}

// Configure loads the given configurations in the engine. Any wrong combination will return an error
func (db *Database) Configure(config core.ServerConfig) error {

	if db.config.File == "" {
		return errors.New("database file name is required")
	}

	dbFile := path.Join(config.Datadir, "db", db.config.File)
	if err := os.MkdirAll(filepath.Dir(dbFile), os.ModePerm); err != nil {
		return err
	}

	logrus.Infof("Open database %s", db.config.File)

	var err error
	if db.DB, err = bbolt.Open(dbFile, boltDBFileMode, defaultBBoltOptions); err != nil {
		return err
	}

	return nil
}
