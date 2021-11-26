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

package dag

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/ugradid/ugradid-node/vdr/types"
	"time"
)

// ErrPreviousTransactionMissing indicates one or more of the previous transactions (which the transaction refers to)
// is missing.
var ErrPreviousTransactionMissing = errors.New("transaction is referring to non-existing previous transaction")

// Verifier defines the API of a DAG verifier, used to check the validity of a transaction.
type Verifier func(ctx context.Context, tx Transaction, graph Dag) error

// NewTransactionSignatureVerifier creates a transaction verifier that checks the signature of the transaction.
// It uses the given KeyResolver to resolves keys that aren't embedded in the transaction.
func NewTransactionSignatureVerifier(resolver types.KeyResolver, payload PayloadStore) Verifier {
	return func(ctx context.Context, tx Transaction, dag Dag) error {
		var signingKey crypto.PublicKey
		if tx.SigningKey() != nil {
			if err := tx.SigningKey().Raw(&signingKey); err != nil {
				return err
			}
		} else {
			st := false
			for _, prev := range tx.Previous() {
				present, err := payload.IsPresent(ctx, prev)
				if err != types.ErrNotFound {
					return err
				}
				if !present {
					st = true
				}
			}
			if st {
				return ErrPreviousTransactionMissing
			}

			pk, err := resolver.ResolvePublicKey(tx.SigningKeyID(), tx.Previous())
			if err != nil {
				return fmt.Errorf("unable to verify transaction signature, can't resolve key by TX ref (kid=%s, tx=%s): %w", tx.SigningKeyID(), tx.Ref().String(), err)
			}
			signingKey = pk
		}
		_, err := jws.Verify(tx.Data(), jwa.SignatureAlgorithm(tx.SigningAlgorithm()), signingKey)
		return err
	}
}

// NewPrevTransactionsVerifier creates a transaction verifier that asserts that all previous transactions are known.
func NewPrevTransactionsVerifier() Verifier {
	return func(ctx context.Context, tx Transaction, graph Dag) error {
		for _, prev := range tx.Previous() {
			present, err := graph.IsPresent(ctx, prev)
			if err != nil {
				return err
			}
			if !present {
				return ErrPreviousTransactionMissing
			}
		}
		return nil
	}
}

// NewSigningTimeVerifier creates a transaction verifier that asserts that signing time of transactions aren't
// further than 1 day in the future, since that complicates head calculation.
func NewSigningTimeVerifier() Verifier {
	return func(_ context.Context, tx Transaction, _ Dag) error {
		if time.Now().Add(24 * time.Hour).Before(tx.SigningTime()) {
			return fmt.Errorf("transaction signing time too far in the future: %s", tx.SigningTime())
		}
		return nil
	}
}