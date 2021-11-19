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
	"github.com/ugradid/ugradid-node/core"
	cryptoHash "github.com/ugradid/ugradid-node/crypto/hash"
	"github.com/ugradid/ugradid-node/network"
	"net/http"
)

// Wrapper implements the ServerInterface for the network API.
type Wrapper struct {
	Service network.Transactions
}

// Preprocess is called just before the API operation itself is invoked.
func (a *Wrapper) Preprocess(operationID string, context echo.Context) {
	context.Set(core.OperationIDContextKey, operationID)
	context.Set(core.ModuleNameContextKey, network.ModuleName)
}

func (a *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, a)
}

// ListTransactions lists all transactions
func (a Wrapper) ListTransactions(ctx echo.Context) error {
	transactions, err := a.Service.ListTransactions()
	if err != nil {
		return err
	}
	results := make([]string, len(transactions))
	for i, transaction := range transactions {
		results[i] = string(transaction.Data())
	}
	return ctx.JSON(http.StatusOK, results)
}

// GetTransaction returns a specific transaction
func (a Wrapper) GetTransaction(ctx echo.Context, hashAsString string) error {
	hash, err := parseHash(hashAsString)
	if err != nil {
		return err
	}
	transaction, err := a.Service.GetTransaction(hash)
	if err != nil {
		return err
	}
	if transaction == nil {
		return core.NotFoundError("transaction not found")
	}
	ctx.Response().Header().Set(echo.HeaderContentType, "application/jose")
	ctx.Response().WriteHeader(http.StatusOK)
	_, err = ctx.Response().Writer.Write(transaction.Data())
	return err
}

// GetTransactionPayload returns the payload of a specific transaction
func (a Wrapper) GetTransactionPayload(ctx echo.Context, hashAsString string) error {
	hash, err := parseHash(hashAsString)
	if err != nil {
		return err
	}
	data, err := a.Service.GetTransactionPayload(hash)
	if err != nil {
		return err
	}
	if data == nil {
		return core.NotFoundError("transaction or contents not found")
	}
	ctx.Response().Header().Set(echo.HeaderContentType, "application/octet-stream")
	ctx.Response().WriteHeader(http.StatusOK)
	_, err = ctx.Response().Writer.Write(data)
	return err
}

func parseHash(hashAsString string) (cryptoHash.SHA256Hash, error) {
	hash, err := cryptoHash.ParseHex(hashAsString)
	if err != nil {
		return hash, core.InvalidInputError("invalid hash: %w", err)
	}
	return hash, err
}