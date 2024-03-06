// Package plasmactlmeta implements meta launchr plugin
package plasmactlmeta

import (
	"bytes"
	"fmt"
	"github.com/launchrctl/launchr/pkg/cli"
	"os"
	"os/exec"
	"sync"

	"github.com/launchrctl/keyring"
	"github.com/launchrctl/launchr"
	"github.com/spf13/cobra"
)

func init() {
	launchr.RegisterPlugin(&Plugin{})
}

// Plugin is launchr plugin providing meta action.
type Plugin struct {
	k keyring.Keyring
}

// PluginInfo implements launchr.Plugin interface.
func (p *Plugin) PluginInfo() launchr.PluginInfo {
	return launchr.PluginInfo{
		Weight: 20,
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
	//cmd := exec.Command("plasmactl", "bump")
	var err error
	//cmd.Stdout = os.Stdout
	//cmd.Stderr = os.Stderr
	//cmd.Stdin = os.Stdin
	//_ = cmd.Run()

	//fmt.Println()
	//cmd = exec.Command("plasmactl", "compose", "--skip-not-versioned", "--conflicts-verbosity")
	//cmd.Stdout = os.Stdout
	//cmd.Stderr = os.Stderr
	//cmd.Stdin = os.Stdin
	//err := cmd.Run()
	//if err != nil {
	//	if exitErr, ok := err.(*exec.ExitError); ok {
	//		os.Exit(exitErr.ExitCode())
	//	} else {
	//		fmt.Println("Error:", err)
	//		os.Exit(1)
	//	}
	//}

	//fmt.Println()
	//cmd = exec.Command("plasmactl", "platform:sync", "dev")
	//cmd.Stdout = os.Stdout
	//cmd.Stderr = os.Stderr
	//cmd.Stdin = os.Stdin
	//err = cmd.Run()
	//if err != nil {
	//	if exitErr, ok := err.(*exec.ExitError); ok {
	//		os.Exit(exitErr.ExitCode())
	//	} else {
	//		fmt.Println("Error:", err)
	//		os.Exit(1)
	//	}
	//}

	fmt.Println()
	var packageStdOut bytes.Buffer
	var packageStdErr bytes.Buffer
	var packageErr error
	var publishStdOut bytes.Buffer
	var publishStdErr bytes.Buffer
	var publishErr error
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		fmt.Println("100")
		defer wg.Done()
		packageCmd := exec.Command("plasmactl", "package")
		packageCmd.Stdout = &packageStdOut
		packageCmd.Stderr = &packageStdErr
		packageCmd.Stdin = os.Stdin
		packageErr = packageCmd.Run()
		if packageErr != nil {
			return
		}
		publishCmd := exec.Command("plasmactl", "publish")
		publishCmd.Stdout = &publishStdOut
		publishCmd.Stderr = &publishStdErr
		publishCmd.Stdin = os.Stdin
		publishErr = publishCmd.Run()
		if publishErr != nil {
			return
		}
	}(wg)

	//wg.Add(1)
	//go func(wg *sync.WaitGroup) {
	//	defer wg.Done()
	//	cmd = exec.Command("plasmactl", "platform:deploy", "dev", "interaction.applications.repositories")
	//	cmd.Stdout = os.Stdout
	//	cmd.Stderr = os.Stderr
	//	cmd.Stdin = os.Stdin
	//	err = cmd.Run()
	//	if err != nil {
	//		if exitErr, ok := err.(*exec.ExitError); ok {
	//			os.Exit(exitErr.ExitCode())
	//		} else {
	//			fmt.Println("Error:", err)
	//			os.Exit(1)
	//		}
	//	}
	//}(wg)
	wg.Wait()
	fmt.Println(packageStdOut.String())
	fmt.Println(packageStdErr.String())
	fmt.Println(publishStdOut.String())
	fmt.Println(publishStdErr.String())
	if exitErr, ok := err.(*exec.ExitError); ok {
		os.Exit(exitErr.ExitCode())
	} else {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	return nil
}

//TODO:
// - wrap stdin to buffer and display it after everything
// - make sure exit code is forwaded after wait group
// - change cmd. by other names
// - check if package does create artifact in background
// - check if with publish keyring, artifact is uploaded in background
// - implement same options as commands used

//return errors.New("error opening artifact file")
//log.Info("LOG INFO")
//if err != nil {
//log.Debug("%s", err)
//return errors.New("something wrong doing this")
//}
