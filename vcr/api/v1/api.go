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

package v1

import (
	"github.com/labstack/echo/v4"
	ssi "github.com/ugradid/ugradid-common"
	"github.com/ugradid/ugradid-node/core"
	"github.com/ugradid/ugradid-node/vcr"
	"github.com/ugradid/ugradid-node/vcr/credential"
	"github.com/ugradid/ugradid-node/vdr/types"
	"net/http"
	"time"
)

var _ ServerInterface = (*Wrapper)(nil)
var _ ErrorStatusCodeResolver = (*Wrapper)(nil)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	Vcr vcr.Vcr
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		vcr.ErrNotFound:          http.StatusNotFound,
		vcr.ErrRevoked:           http.StatusConflict,
		credential.ErrValidation: http.StatusBadRequest,
		types.ErrNotFound:        http.StatusBadRequest,
		types.ErrKeyNotFound:     http.StatusBadRequest,
		vcr.ErrInvalidCredential: http.StatusNotFound,
	})
}

// Preprocess is called just before the API operation itself is invoked.
func (w *Wrapper) Preprocess(operationID string, context echo.Context) {
	context.Set(core.StatusCodeResolverContextKey, w)
	context.Set(core.OperationIDContextKey, operationID)
	context.Set(core.ModuleNameContextKey, "vcr")
}

// Routes registers the handler to the echo router
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, w)
}

// Create a Verifiable credential
func (w *Wrapper) Create(ctx echo.Context) error {
	requestedVC := IssueVCRequest{}

	if err := ctx.Bind(&requestedVC); err != nil {
		return err
	}

	vcCreated, err := w.Vcr.Issue(requestedVC)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, vcCreated)
}

// Resolve a Verifiable credential
func (w *Wrapper) Resolve(ctx echo.Context) error {
	requestedVC := ResolveVCRequest{}

	if err := ctx.Bind(&requestedVC); err != nil {
		return err
	}

	idURI, err := ssi.ParseURI(requestedVC.Id)
	// return 400 for malformed input
	if err != nil {
		return core.InvalidInputError("failed to parse credential ID: %w", err)
	}

	// resolve time
	var at *time.Time
	if requestedVC.ResolveTime != nil {
		parsedTime, err := time.Parse(time.RFC3339, *requestedVC.ResolveTime)
		if err != nil {
			return core.InvalidInputError("failed to parse query parameter 'at': %w", err)
		}
		at = &parsedTime
	}

	// id is given with fragment
	vc, err := w.Vcr.Resolve(*idURI, requestedVC.CredentialType, at)
	if vc == nil && err != nil {
		return err
	}

	// transform VC && error
	result := ResolutionResult{
		CurrentStatus:        ResolutionResultCurrentStatusTrusted,
		VerifiableCredential: *vc,
	}

	switch err {
	case vcr.ErrUntrusted:
		result.CurrentStatus = ResolutionResultCurrentStatusUntrusted
	case vcr.ErrRevoked:
		result.CurrentStatus = ResolutionResultCurrentStatusRevoked
	}

	return ctx.JSON(http.StatusOK, result)
}
