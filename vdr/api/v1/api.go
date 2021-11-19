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
	"github.com/ugradid/ugradid-common/did"
	"github.com/ugradid/ugradid-node/core"
	vdrDoc "github.com/ugradid/ugradid-node/vdr/doc"
	"github.com/ugradid/ugradid-node/vdr/types"
	"net/http"
)

var _ ServerInterface = (*Wrapper)(nil)
var _ ErrorStatusCodeResolver = (*Wrapper)(nil)

// Wrapper is needed to connect the implementation to the echo ServiceWrapper
type Wrapper struct {
	VDR         types.Vdr
	DocResolver types.DocResolver
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (a *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		types.ErrNotFound:                http.StatusNotFound,
		types.ErrDIDNotManagedByThisNode: http.StatusForbidden,
		types.ErrDeactivated:             http.StatusConflict,
		types.ErrNoActiveController:      http.StatusConflict,
		types.ErrDuplicateService:        http.StatusBadRequest,
		vdrDoc.ErrInvalidOptions:         http.StatusBadRequest,
		did.ErrInvalidDID:                http.StatusBadRequest,
	})
}

// Preprocess is called just before the API operation itself is invoked.
func (a *Wrapper) Preprocess(operationID string, context echo.Context) {
	context.Set(core.StatusCodeResolverContextKey, a)
	context.Set(core.OperationIDContextKey, operationID)
	context.Set(core.ModuleNameContextKey, "vdr")
}

func (a *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, a)
}

// CreateDID creates a new DID Document and returns it.
func (a Wrapper) CreateDID(ctx echo.Context) error {
	req := DIDCreateRequest{}
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	options := vdrDoc.DefaultCreationOptions()
	if req.Controllers != nil {
		for _, c := range *req.Controllers {
			id, err := did.ParseDID(c)
			if err != nil {
				return core.InvalidInputError("controller entry (%s) could not be parsed: %w", c, err)
			}
			options.Controllers = append(options.Controllers, *id)
		}
	}

	if req.Authentication != nil {
		options.Authentication = *req.Authentication
	}
	if req.AssertionMethod != nil {
		options.AssertionMethod = *req.AssertionMethod
	}
	if req.CapabilityDelegation != nil {
		options.CapabilityDelegation = *req.CapabilityDelegation
	}
	if req.CapabilityInvocation != nil {
		options.CapabilityInvocation = *req.CapabilityInvocation
	}
	if req.KeyAgreement != nil && *req.KeyAgreement {
		options.KeyAgreement = *req.KeyAgreement
	}
	if req.SelfControl != nil {
		options.SelfControl = *req.SelfControl
	}

	doc, _, err := a.VDR.Create(options)
	// if this operation leads to an error, it may return a 500
	if err != nil {
		return err
	}

	// this API returns a DIDDocument according to spec so it may return the business object
	return ctx.JSON(http.StatusOK, *doc)
}