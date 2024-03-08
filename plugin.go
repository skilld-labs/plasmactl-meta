// Package plasmactlmeta implements meta launchr plugin
package plasmactlmeta

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/launchrctl/launchr/pkg/cli"

	"github.com/launchrctl/keyring"
	"github.com/launchrctl/launchr"
	"github.com/launchrctl/launchr/pkg/log"
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
		Weight: 1337,
	}
}

// OnAppInit implements launchr.Plugin interface.
func (p *Plugin) OnAppInit(app launchr.App) error {
	app.GetService(&p.k)
	return nil
}

// CobraAddCommands implements launchr.CobraPlugin interface to provide meta functionality.
func (p *Plugin) CobraAddCommands(rootCmd *cobra.Command) error {
	var metaCmd = &cobra.Command{
		Use:   "meta [flags] environment tags",
		Short: "Executes bump + compose + sync + package + publish + deploy",
		Args:  cobra.MatchAll(cobra.ExactArgs(2), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Don't show usage help on a runtime error.
			cmd.SilenceUsage = true
			keyringPassphrase, err := cmd.Flags().GetString("keyring-passphrase")
			if err != nil {
				log.Fatal("error while getting keyringPassphrase option value: ", err)
			}

			return meta(args[0], args[1], keyringPassphrase, p.k)
		},
	}
	metaCmd.SetArgs([]string{"environment", "tags"})

	rootCmd.AddCommand(metaCmd)
	return nil
}

func meta(environment, tags, keyringPassphrase string, k keyring.Keyring) error {
	log.Info(fmt.Sprintf("ENVIRONMENT: %s", environment))
	log.Info(fmt.Sprintf("TAGS: %s", tags))
	log.Info(fmt.Sprintf("KEYRING PW: %s\n", keyringPassphrase))

	time.Sleep(1000 * time.Minute) // TODO: Remove after tests

	bumpCmd := exec.Command("plasmactl", "bump")
	bumpCmd.Stdout = os.Stdout
	bumpCmd.Stderr = os.Stderr
	bumpCmd.Stdin = os.Stdin
	_ = bumpCmd.Run()

	fmt.Println()
	composeCmd := exec.Command("plasmactl", "compose", "--skip-not-versioned", "--conflicts-verbosity", "--keyring-passphrase", "X")
	composeCmd.Stdout = os.Stdout
	composeCmd.Stderr = os.Stderr
	composeCmd.Stdin = os.Stdin
	composeErr := composeCmd.Run()
	if composeErr != nil {
		if exitErr, ok := composeErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		} else {
			fmt.Println("Error:", composeErr)
			os.Exit(1)
		}
	}

	fmt.Println()
	syncCmd := exec.Command("plasmactl", "platform:sync", "dev")
	//syncCmd = exec.Command("plasmactl", "bump", "--sync", "dev", "--keyring-passphrase", "X")
	syncCmd.Stdout = os.Stdout
	syncCmd.Stderr = os.Stderr
	syncCmd.Stdin = os.Stdin
	syncErr := syncCmd.Run()
	if syncErr != nil {
		if exitErr, ok := syncErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		} else {
			fmt.Println("Error:", syncErr)
			os.Exit(1)
		}
	}

	var packageStdOut bytes.Buffer
	var packageStdErr bytes.Buffer
	var packageErr error

	var publishStdOut bytes.Buffer
	var publishStdErr bytes.Buffer
	var publishErr error

	fmt.Println()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		cli.Println("--Starting waitgroup 1")
		defer wg.Done()

		packageCmd := exec.Command("plasmactl", "package")
		packageCmd.Stdout = &packageStdOut
		packageCmd.Stderr = &packageStdErr
		//publishCmd.Stdin = os.Stdin // Any interaction will prevent waitgroup to finish and thus stuck before print of stdout
		packageErr = packageCmd.Run()
		if packageErr != nil {
			return
		}

		//publishCmd := exec.Command("plasmactl", "publish")
		publishCmd := exec.Command("plasmactl", "publish", "--keyring-passphrase", "X")
		publishCmd.Stdout = &publishStdOut
		publishCmd.Stderr = &publishStdErr
		//publishCmd.Stdin = os.Stdin // Any interaction will prevent waitgroup to finish and thus stuck before print of stdout
		publishErr = publishCmd.Run()
		if publishErr != nil {
			return
		}
		cli.Println("--Exiting waitgroup 1")
	}(wg)

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		cli.Println("--Starting waitgroup 2")
		defer wg.Done()
		//deployCmd := exec.Command("plasmactl", "platform:deploy", "dev", "interaction.applications.repositories")
		deployCmd := exec.Command("ls", "-lah")
		deployCmd.Stdout = os.Stdout
		deployCmd.Stderr = os.Stderr
		deployCmd.Stdin = os.Stdin
		deployErr := deployCmd.Run()
		if deployErr != nil {
			if exitErr, ok := deployErr.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			} else {
				fmt.Println("Error:", deployErr)
				os.Exit(1)
			}
		}
		cli.Println("--Ending waitgroup 2")
	}(wg)
	wg.Wait()

	fmt.Println()
	fmt.Println(packageStdOut.String())
	fmt.Println(packageStdErr.String())
	if packageErr != nil {
		if exitErr, ok := packageErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		} else {
			fmt.Println("Error:", packageErr)
			os.Exit(1)
		}
	}

	fmt.Println()
	fmt.Println(publishStdOut.String())
	fmt.Println(publishStdErr.String())
	if publishErr != nil {
		if exitErr, ok := publishErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		} else {
			fmt.Println("Error:", publishErr)
			os.Exit(1)
		}
	}

	return nil
}

//TODO:
// - check if package does create artifact in background
// - check if with publish keyring, artifact is uploaded in background
// - implement same options as commands used

//return errors.New("error opening artifact file")
//log.Info("LOG INFO")
//if err != nil {
//log.Debug("%s", err)
//return errors.New("something wrong doing this")
//}
