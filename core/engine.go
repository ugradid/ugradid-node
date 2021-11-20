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
	"github.com/spf13/cobra"
	"os"
)

// Routable enables connecting a REST API to the echo server.
type Routable interface {
	Routes(router EchoRouter)
}

// Engine is the base interface for a modular design
type Engine interface{}

// System is the control structure where engines are registered.
type System struct {
	// engines is the slice of all registered engines
	engines []Engine
	// Config holds the global and raw config
	Config *ServerConfig
	// Routers are used to connect API handlers to the echo server
	Routers []Routable
	// EchoCreator is the function that's used to create the echo server/
	EchoCreator func(cfg HTTPConfig,
		authProvider func(AuthType) (HTTPAuthenticator, error), strictmode bool) (EchoServer, error)
}

// NewSystem creates a new, empty System.
func NewSystem() *System {
	result := &System{
		engines: []Engine{},
		Config:  NewServerConfig(),
		Routers: []Routable{},
	}

	result.EchoCreator = func(cfg HTTPConfig,
		authProvider func(AuthType) (HTTPAuthenticator, error), strictmode bool) (EchoServer, error) {
		return createEchoServer(cfg, authProvider, strictmode)
	}
	return result
}

// RegisterEngine is a helper func to add an engine to the list
func (system *System) RegisterEngine(engine Engine) {
	system.engines = append(system.engines, engine)
}

// RegisterRoutes is a helper func to register API routers
func (system *System) RegisterRoutes(router Routable) {
	system.Routers = append(system.Routers, router)
}

// Configure configures all engines in the system.
func (system *System) Configure() error {
	var err error
	if err = os.MkdirAll(system.Config.Datadir, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create datadir (dir=%s): %w", system.Config.Datadir, err)
	}
	return system.VisitEnginesE(func(engine Engine) error {
		// only if Engine is dynamically configurable
		if m, ok := engine.(Configurable); ok {
			err = m.Configure(*system.Config)
		}
		return err
	})
}

// Load loads the config and injects config values into engines
func (system *System) Load(cmd *cobra.Command) error {
	if err := system.Config.Load(cmd); err != nil {
		return err
	}

	return system.VisitEnginesE(func(engine Engine) error {
		if m, ok := engine.(Injectable); ok {
			return system.Config.InjectIntoEngine(m)
		}

		return nil
	})
}

// Shutdown shuts down all engines in the system.
func (system *System) Shutdown() error {
	var err error
	return system.VisitEnginesE(func(engine Engine) error {
		if m, ok := engine.(Runnable); ok {
			err = m.Shutdown()
		}
		return err
	})
}

// Start starts all engines in the system.
func (system *System) Start() error {
	var err error
	return system.VisitEnginesE(func(engine Engine) error {
		if m, ok := engine.(Runnable); ok {
			err = m.Start()
		}
		return err
	})
}

// VisitEngines applies the given function on all engines in the system.
func (system *System) VisitEngines(visitor func(engine Engine)) {
	_ = system.VisitEnginesE(func(engine Engine) error {
		visitor(engine)
		return nil
	})
}

// VisitEnginesE applies the given function on all engines in the system,
//stopping when an error is returned.
func (system *System) VisitEnginesE(visitor func(engine Engine) error) error {
	for _, e := range system.engines {
		if err := visitor(e); err != nil {
			return err
		}
	}

	return nil
}

// Runnable is the interface that groups the Start and Shutdown methods.
// When an engine implements these they will be called on startup and shutdown.
// Start and Shutdown should not be called more than once
type Runnable interface {
	Start() error
	Shutdown() error
}

// Configurable is the interface that contains the Configure method.
// When an engine implements the Configurable interface, it will be called before startup.
// Configure should only be called once per engine instance
type Configurable interface {
	Configure(config ServerConfig) error
}

// Named is the interface for all engines that have a name
type Named interface {
	// Name returns the name of the engine
	Name() string
}

// Injectable marks an engine capable of Config injection
type Injectable interface {
	Named
	// Config returns a pointer to the struct that holds the Config.
	Config() interface{}
}
