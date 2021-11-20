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

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type HTTPAuthenticator interface {
	authenticator() echo.MiddlewareFunc
}

type noopAuthenticator struct{}

func (n noopAuthenticator) authenticator() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(context echo.Context) error {
			return next(context)
		}
	}
}

func HTTPAuthenticatorProvider(secret string) func(authType AuthType) (HTTPAuthenticator, error) {
	return func(authType AuthType) (HTTPAuthenticator, error) {
		switch authType {
		case TokenAuthType:
			return NewTokenAuthenticator(secret)
		case NoAuthAuthType:
			fallthrough
		case "":
			return noopAuthenticator{}, nil
		default:
			return nil, fmt.Errorf("invalid auth type: %s", authType)
		}
	}
}

func NewTokenAuthenticator(secret string) (*TokenAuthenticator, error) {
	if secret == "" {
		return nil, fmt.Errorf("HTTP secret is not empty")
	}
	return &TokenAuthenticator{secret: secret}, nil
}

type TokenAuthenticator struct {
	secret string
}

func (p *TokenAuthenticator) authenticator() echo.MiddlewareFunc {
	return middleware.JWT([]byte(p.secret))
}

func (p *TokenAuthenticator) CreateToken() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	return token.SignedString([]byte(p.secret))
}
