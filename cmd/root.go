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

package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/ugradid/ugradid-node/core"
	"github.com/ugradid/ugradid-node/crypto"
	"github.com/ugradid/ugradid-node/network"
	networkAPI "github.com/ugradid/ugradid-node/network/api/v1"
	"github.com/ugradid/ugradid-node/vcr"
	vcrAPI "github.com/ugradid/ugradid-node/vcr/api/v1"
	"github.com/ugradid/ugradid-node/vdr"
	vdrAPI "github.com/ugradid/ugradid-node/vdr/api/v1"
	vdrCmd "github.com/ugradid/ugradid-node/vdr/cmd"
	"github.com/ugradid/ugradid-node/vdr/doc"
	"github.com/ugradid/ugradid-node/vdr/store"
	"io"
	"os"
)

var stdOutWriter io.Writer = os.Stdout

func createRootCommand() *cobra.Command {
	return &cobra.Command{
		Use: "ugradid",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}
}

func createPrintConfigCommand(system *core.System) *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Prints the current config",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load all config and add generic options
			cmd.PersistentFlags().AddFlagSet(core.FlagSet())
			if err := system.Load(cmd); err != nil {
				return err
			}
			cmd.Println("Current system config")
			cmd.Println(system.Config.PrintConfig())
			return nil
		},
	}
}

func createServerCommand(system *core.System) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Starts the ugradid server",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load all config and add generic options
			if err := system.Load(cmd); err != nil {
				return err
			}
			if err := startServer(system); err != nil {
				return err
			}
			return nil
		},
	}
	addFlagSets(cmd)
	return cmd
}

func startServer(system *core.System) error {
	logrus.Info("Starting server")

	// check config on all engines
	if err := system.Configure(); err != nil {
		return err
	}

	// start engines
	if err := system.Start(); err != nil {
		return err
	}

	// init HTTP interfaces and routes
	echoServer, err := core.CreateEchoServer(
		system.Config.HTTP,
		system.Config.Strictmode)

	if err != nil {
		return err
	}

	for _, r := range system.Routers {
		r.Routes(echoServer)
	}

	defer func() {
		if err := system.Shutdown(); err != nil {
			logrus.Error("Error shutting down system:", err)
		}
	}()

	if err := echoServer.Start(system.Config.HTTP.Address); err != nil {
		return err
	}
	return nil
}

// CreateSystem creates the system and registers all default engines.
func CreateSystem() *core.System {

	system := core.NewSystem()

	// Create instances
	vdrStoreInstance := store.NewVdrStoreInstance()

	keyResolver := doc.KeyResolver{Store: vdrStoreInstance}

	docResolver := doc.Resolver{Store: vdrStoreInstance}

	cryptoInstance := crypto.NewCryptoInstance()

	networkInstance := network.NewNetworkInstance(
		network.DefaultConfig(), keyResolver)

	vdrInstance := vdr.NewVdr(
		vdr.DefaultConfig(), cryptoInstance, networkInstance, vdrStoreInstance)

	vcrInstance := vcr.NewVCRInstance(
		cryptoInstance, docResolver, keyResolver, networkInstance)

	// Register HTTP routes
	system.RegisterRoutes(&networkAPI.Wrapper{Service: networkInstance})

	system.RegisterRoutes(&vdrAPI.Wrapper{VDR: vdrInstance, DocResolver: docResolver})

	system.RegisterRoutes(&vcrAPI.Wrapper{ Vcr: vcrInstance})

	// Register engines
	system.RegisterEngine(vdrStoreInstance)
	system.RegisterEngine(cryptoInstance)
	system.RegisterEngine(networkInstance)
	system.RegisterEngine(vdrInstance)
	system.RegisterEngine(vcrInstance)

	return system
}

func CreateCommand(system *core.System) *cobra.Command {
	command := createRootCommand()
	command.SetOut(stdOutWriter)
	addSubCommands(system, command)
	return command
}

func addSubCommands(system *core.System, root *cobra.Command) {
	// Register server commands
	root.AddCommand(createServerCommand(system))
	root.AddCommand(createPrintConfigCommand(system))
}

// Execute registers all engines into the system and executes the root command.
func Execute(system *core.System) {
	command := CreateCommand(system)
	command.SetOut(stdOutWriter)

	// blocking main call
	command.Execute()
}

func addFlagSets(cmd *cobra.Command) {
	cmd.PersistentFlags().AddFlagSet(core.FlagSet())
	cmd.PersistentFlags().AddFlagSet(vdrCmd.FlagSet())
}
