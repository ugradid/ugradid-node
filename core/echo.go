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
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"strings"
)

// EchoServer implements both the EchoRouter interface and Start function
type EchoServer interface {
	EchoRouter
	Start(address string) error
}

// EchoRouter is the interface the generated server API's will require as the Routes func argument
type EchoRouter interface {
	Add(method string, path string, handler echo.HandlerFunc,
		middleware ...echo.MiddlewareFunc) *echo.Route
}

func CreateEchoServer(cfg HTTPConfig, strictmode bool) (*echo.Echo, error) {
	echoServer := echo.New()
	echoServer.HideBanner = true

	// ErrorHandler
	echoServer.HTTPErrorHandler = createHTTPErrorHandler()

	// CORS Configuration
	if cfg.CORS.Enabled() {
		if strictmode {
			for _, origin := range cfg.CORS.Origin {
				if strings.TrimSpace(origin) == "*" {
					return nil, errors.New("wildcard CORS origin is not allowed in strict mode")
				}
			}
		}
		echoServer.Use(middleware.CORSWithConfig(middleware.CORSConfig{AllowOrigins: cfg.CORS.Origin}))
	}

	// Use middleware to decode URL encoded path parameters like did%3Augra%3A123 -> did:ugra:123
	echoServer.Use(DecodeURIPath)

	echoServer.Use(loggerMiddleware(loggerConfig{Skipper: requestsStatusEndpoint, logger: Logger()}))

	return echoServer, nil
}

func requestsStatusEndpoint(context echo.Context) bool {
	return context.Request().RequestURI == "/status"
}

// DecodeURIPath is a echo middleware that decodes path parameters
func DecodeURIPath(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		newValues := make([]string, len(c.ParamValues()))
		for i, value := range c.ParamValues() {
			path, err := url.PathUnescape(value)
			if err != nil {
				path = value
			}
			newValues[i] = path
		}
		c.SetParamNames(c.ParamNames()...)
		c.SetParamValues(newValues...)
		return next(c)
	}
}


var _logger = logrus.StandardLogger().WithField("module", "http-server")

func Logger() *logrus.Entry {
	return _logger
}

// loggerConfig Contains the configuration for the loggerMiddleware.
// Currently, this only allows for configuration of skip paths
type loggerConfig struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper
	logger  *logrus.Entry
}

func loggerMiddleware(config loggerConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			if config.Skipper != nil && config.Skipper(c) {
				return next(c)
			}
			err = next(c)
			req := c.Request()
			res := c.Response()

			status := res.Status
			if err != nil {
				switch errWithStatus := err.(type) {
				case *echo.HTTPError:
					status = errWithStatus.Code
				case httpStatusCodeError:
					status = errWithStatus.statusCode
				default:
					status = http.StatusInternalServerError
				}
			}

			config.logger.WithFields(logrus.Fields{
				"remote_ip": c.RealIP(),
				"method":    req.Method,
				"uri":       req.RequestURI,
				"status":    status,
			}).Info("Request")
			return
		}
	}
}