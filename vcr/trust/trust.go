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

package trust

import (
	"errors"
	ssi "github.com/ugradid/ugradid-common"
	"gopkg.in/yaml.v3"
	"os"
	"sync"
)

// ErrNoFilename is returned when trust actions are performed but no file for storing this is specified.
var ErrNoFilename = errors.New("no filename specified")

// Config holds the trusted issuers per credential type
type Config struct {
	filename       string
	issuersPerType map[string][]string
	mutex          sync.Mutex
}

// NewConfig returns a fully configured Config
func NewConfig(filename string) *Config {
	return &Config{
		filename:       filename,
		issuersPerType: map[string][]string{},
		mutex:          sync.Mutex{},
	}
}

// Load the trusted issuers per credential type from file
func (tc *Config) Load() error {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	if tc.filename == "" {
		return ErrNoFilename
	}

	// ignore if not exists
	_, err := os.Stat(tc.filename)
	if err != nil {
		return nil
	}

	data, err := os.ReadFile(tc.filename)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, &tc.issuersPerType)
}

// Save the list of trusted issuers per credential type to file
func (tc *Config) save() error {
	if tc.filename == "" {
		return ErrNoFilename
	}

	data, err := yaml.Marshal(tc.issuersPerType)
	if err != nil {
		return err
	}

	return os.WriteFile(tc.filename, data, 0644)
}

// List returns all trusted issuers for the given type
func (tc *Config) List(credentialType string) []ssi.URI {
	stringList := tc.issuersPerType[credentialType]
	uriList := make([]ssi.URI, len(stringList))
	for i, e := range stringList {
		u, _ := ssi.ParseURI(e)
		uriList[i] = *u
	}
	return uriList
}

// IsTrusted returns true when the given issuer is in the trusted issuers list of the given credentialType
func (tc *Config) IsTrusted(credentialType string, issuer ssi.URI) bool {
	issuerString := issuer.String()
	for _, i := range tc.issuersPerType[credentialType] {
		if i == issuerString {
			return true
		}
	}

	return false
}

// AddTrust adds trust in a specific Issuer for a credential type.
// It returns an error if the Save fails
func (tc *Config) AddTrust(credentialType string, issuer ssi.URI) error {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	if tc.IsTrusted(credentialType, issuer) {
		return nil
	}

	tc.issuersPerType[credentialType] = append(tc.issuersPerType[credentialType], issuer.String())

	return tc.save()
}

// RemoveTrust removes trust in a specific Issuer for a credential type.
// It returns an error if the Save fails
func (tc *Config) RemoveTrust(credentialType string, issuer ssi.URI) error {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	if !tc.IsTrusted(credentialType, issuer) {
		return nil
	}

	var issuerList = make([]string, len(tc.issuersPerType[credentialType])-1)
	j := 0
	for _, i := range tc.issuersPerType[credentialType] {
		if i != issuer.String() {
			issuerList[j] = i
			j++
		}
	}

	tc.issuersPerType[credentialType] = issuerList

	return tc.save()
}