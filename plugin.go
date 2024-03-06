// Package plasmactlmeta implements meta launchr plugin
package plasmactlmeta

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/launchrctl/launchr/pkg/cli"

	"github.com/launchrctl/keyring"
	"github.com/launchrctl/launchr"
	"github.com/launchrctl/launchr/pkg/log"
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

	cli.Println("XXXXX")

	cmd := exec.Command("plasmactl", "bump")
	if err := cmd.Run(); err != nil {
		fmt.Println("Error executing bump:", err)
		os.Exit(1)
	}

	cmd = exec.Command("plasmactl", "compose", "--skip-not-versioned", "--conflicts-verbosity")
	if err := cmd.Run(); err != nil {
		fmt.Println("Error executing compose:", err)
		os.Exit(1)
	}

	log.Info("XXXX")

	cli.Println("XXXXX")

	//if err != nil {
	//return errors.New("error opening artifact file")
	//}
	//log.Debug("%s", err)

	return nil
}
