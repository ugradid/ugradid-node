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
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"sync"
)

// DefaultEchoGroup group for all access route
const DefaultEchoGroup = ""

// EchoServer implements both the EchoRouter interface and Start function
type EchoServer interface {
	EchoRouter
	Start(address string) error
}

// NewMultiEcho creates a new MultiEcho which uses the given function to create EchoServers. If a route is registered
// for an unknown group is is bound to the given defaultInterface.
func NewMultiEcho(creatorFn func(cfg HTTPConfig) (EchoServer, error)) *MultiEcho {
	return &MultiEcho{
		interfaces:      map[string]EchoServer{},
		groups:          map[string]string{},
		groupMiddleware: map[string]echo.MiddlewareFunc{},
		creatorFn:       creatorFn,
	}
}

// MultiEcho allows to bind specific URLs to specific HTTP interfaces
type MultiEcho struct {
	interfaces      map[string]EchoServer
	groups          map[string]string
	groupMiddleware map[string]echo.MiddlewareFunc
	creatorFn       func(cfg HTTPConfig) (EchoServer, error)
}

// Add adds a route to the Echo server.
func (c *MultiEcho) Add(method, path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) *echo.Route {

	group := getGroup(path)
	groupAddress := c.groups[group]

	var iface EchoServer

	if groupAddress != "" {
		iface = c.interfaces[groupAddress]
	} else {
		iface = c.interfaces[c.groups[DefaultEchoGroup]]
	}

	return iface.Add(method, path, handler, middleware...)
}

// Get the group name from the path URL. The group is computed up to the first slash in the path.
func getGroup(path string) string {
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			return strings.ToLower(part)
		}
	}
	return ""
}

// Bind binds the given group (first part of the URL) to the given HTTP interface. Calling Bind for the same group twice
// results in an error being returned.
func (c *MultiEcho) Bind(group string, interfaceConfig HTTPConfig) error {
	normGroup := strings.ToLower(group)
	if _, groupExists := c.groups[normGroup]; groupExists {
		return fmt.Errorf("http bind group already exists: %s", group)
	}
	c.groups[group] = interfaceConfig.Address

	if _, addressBound := c.interfaces[interfaceConfig.Address]; !addressBound {
		server, err := c.creatorFn(interfaceConfig)
		if err != nil {
			return err
		}
		c.interfaces[interfaceConfig.Address] = server
	}
	return nil
}

// Start starts all Echo servers.
func (c MultiEcho) Start() error {
	wg := &sync.WaitGroup{}
	wg.Add(len(c.interfaces))
	errChan := make(chan error, len(c.interfaces))
	for address, echoServer := range c.interfaces {
		c.start(address, echoServer, wg, errChan)
	}
	wg.Wait()
	if len(errChan) > 0 {
		return <-errChan
	}
	return nil
}

func (c *MultiEcho) start(address string, server EchoServer, wg *sync.WaitGroup, errChan chan error) {
	go func() {
		if err := server.Start(address); err != nil {
			errChan <- err
		}
		wg.Done()
	}()
}

// EchoRouter is the interface the generated server API's will require as the Routes func argument
type EchoRouter interface {
	Add(method string, path string, handler echo.HandlerFunc,
		middleware ...echo.MiddlewareFunc) *echo.Route
}

func createEchoServer(cfg HTTPConfig,
	authenticatorProvider func(AuthType) (HTTPAuthenticator, error),
	strictmode bool) (*echo.Echo, error) {

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

	// Configure authentication
	auth, err := authenticatorProvider(cfg.Authentication)
	if err != nil {
		return nil, err
	}

	if auth != nil {
		echoServer.Use(auth.authenticator())
	}

	echoServer.Use(loggerMiddleware(loggerConfig{Skipper: requestsStatusEndpoint, logger: Logger()}))

	return echoServer, nil
}

func requestsStatusEndpoint(context echo.Context) bool {
	return context.Request().RequestURI == "/status"
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
