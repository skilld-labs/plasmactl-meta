// Package plasmactlmeta implements meta launchr plugin
package plasmactlmeta

import (
	"bytes"
	"fmt"
	"github.com/launchrctl/launchr/pkg/cli"
	"os"
	"os/exec"

	"io"

	"github.com/launchrctl/keyring"
	"github.com/launchrctl/launchr"
	"github.com/spf13/cobra"
)

func init() {
	launchr.RegisterPlugin(&Plugin{})
}

// Plugin is launchr plugin providing bump action.
type Plugin struct {
	k keyring.Keyring
}

// PluginInfo implements launchr.Plugin interface.
func (p *Plugin) PluginInfo() launchr.PluginInfo {
	return launchr.PluginInfo{
		Weight: 10,
	}
}

// OnAppInit implements launchr.Plugin interface.
func (p *Plugin) OnAppInit(app launchr.App) error {
	app.GetService(&p.k)
	return nil
}

// CobraAddCommands implements launchr.CobraPlugin interface to provide meta functionality.
func (p *Plugin) CobraAddCommands(rootCmd *cobra.Command) error {
	var environment string
	var resources string

	var pblCmd = &cobra.Command{
		Use:   "meta",
		Short: "Executes bump + compose + sync + package + publish + deploy",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Don't show usage help on a runtime error.
			cmd.SilenceUsage = true

			return meta(environment, resources, p.k)
		},
	}

	pblCmd.Flags().StringVarP(&environment, "environment", "", "", "Target environment")
	pblCmd.Flags().StringVarP(&resources, "resources", "", "", "Resources to deploy")

	rootCmd.AddCommand(pblCmd)
	return nil
}

func meta(environment, resources string, k keyring.Keyring) error {
	cli.Println("")
	cmd := exec.Command("plasmactl", "bump")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &stdout)
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	cmd.Stdin = os.Stdin
	_ = cmd.Run()

	fmt.Println()
	cmd = exec.Command("plasmactl", "compose", "--skip-not-versioned", "--conflicts-verbosity")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		} else {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	}

	fmt.Println()
	cmd = exec.Command("plasmactl", "platform:sync", "dev")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	err = cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		} else {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	}

	return nil
}

//return errors.New("error opening artifact file")
//log.Info("LOG INFO")
//if err != nil {
//log.Debug("%s", err)
//return errors.New("something wrong doing this")
//}
