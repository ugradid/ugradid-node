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

package storage

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ugradid/ugradid-node/crypto/util"
	"os"
	"path/filepath"
)

type entryType string

const (
	privateKeyEntry entryType = "private.pem"
	publicKeyEntry  entryType = "public.json"
)

type fileOpenError struct {
	filePath string
	kid      string
	err      error
}

// Error returns the string representation
func (f *fileOpenError) Error() string {
	return fmt.Sprintf("could not open entry %s with filename %s: %v", f.kid, f.filePath, f.err)
}

// Unwrap is needed for fileOpenError to be UnWrapped
func (f *fileOpenError) Unwrap() error {
	return f.err
}

type fileSystemBackend struct {
	fspath string
}

// NewFileSystemBackend creates a new filesystem backend, all directories will be created for the given path
func NewFileSystemBackend(fspath string) (Storage, error) {
	if fspath == "" {
		return nil, errors.New("filesystem path is empty")
	}
	fsc := &fileSystemBackend{
		fspath,
	}

	err := fsc.createDirs()

	if err != nil {
		return nil, err
	}

	return fsc, nil
}

func (fsc *fileSystemBackend) PrivateKeyExists(kid string) bool {
	_, err := os.Stat(fsc.getEntryPath(kid, privateKeyEntry))
	return err == nil
}

// GetPrivateKey Load the privatekey for the given legalEntity from disk.
//Since a legalEntity has a URI as identifier, the URI is
//base64 encoded and postfixed with '_private.pem'.
//Keys are stored in pem format and are 2k RSA keys.
func (fsc *fileSystemBackend) GetPrivateKey(kid string) (crypto.Signer, error) {
	data, err := fsc.readEntry(kid, privateKeyEntry)
	if err != nil {
		return nil, err
	}
	privateKey, err := util.PemToPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// GetPublicKey Load the public key from disk, it load the private key and extract the public key from it.
func (fsc *fileSystemBackend) GetPublicKey(kid string) (PublicKeyEntry, error) {
	data, err := fsc.readEntry(kid, publicKeyEntry)
	publicKeyEntry := PublicKeyEntry{}

	if err != nil {
		return publicKeyEntry, err
	}

	err = json.Unmarshal(data, &publicKeyEntry)

	return publicKeyEntry, err
}

// SavePrivateKey Save the private key for the given key to disk. Files are  postfixed with '_private.pem'.
//Keys are stored in pem format. It also store the public key
func (fsc *fileSystemBackend) SavePrivateKey(kid string, key crypto.PrivateKey) error {
	filenamePath := fsc.getEntryPath(kid, privateKeyEntry)
	outFile, err := os.Create(filenamePath)

	if err != nil {
		return err
	}

	defer outFile.Close()

	pem, err := util.PrivateKeyToPem(key)
	if err != nil {
		return err
	}

	_, err = outFile.Write([]byte(pem))

	return err
}

// SavePublicKey Save the public key for the given key to disk. Files are  postfixed with '_public.json'.
//Keys are stored in JWK format.
func (fsc *fileSystemBackend) SavePublicKey(kid string, entry PublicKeyEntry) error {
	filenamePath := fsc.getEntryPath(kid, publicKeyEntry)
	outFile, err := os.Create(filenamePath)

	if err != nil {
		return err
	}
	defer outFile.Close()

	bytes, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	_, err = outFile.Write(bytes)

	return err
}

func (fsc fileSystemBackend) readEntry(kid string, entryType entryType) ([]byte, error) {
	filePath := fsc.getEntryPath(kid, entryType)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, &fileOpenError{kid: kid, filePath: filePath, err: ErrNotFound}
		}
		return nil, &fileOpenError{kid: kid, filePath: filePath, err: err}
	}
	return data, nil
}

func (fsc fileSystemBackend) getEntryPath(key string, entryType entryType) string {
	return filepath.Join(fsc.fspath, getEntryFileName(key, entryType))
}

func (fsc *fileSystemBackend) createDirs() error {
	f, err := os.Open(fsc.fspath)

	if f != nil {
		f.Close()
	}

	if err != nil {
		err = os.MkdirAll(fsc.fspath, os.ModePerm)
	}

	return err
}

func getEntryFileName(kid string, entryType entryType) string {
	return fmt.Sprintf("%s_%s", kid, entryType)
}