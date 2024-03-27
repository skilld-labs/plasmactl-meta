// Package plasmactlmeta implements meta launchr plugin
package plasmactlmeta

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

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
	var username string
	var password string

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

			return meta(args[0], args[1], keyringPassphrase, username, password, p.k)
		},
	}
	metaCmd.SetArgs([]string{"environment", "tags"})
	metaCmd.Flags().StringVarP(&username, "username", "", "", "Username for artifact repository")
	metaCmd.Flags().StringVarP(&password, "password", "", "", "Password for artifact repository")

	rootCmd.AddCommand(metaCmd)
	return nil
}

func meta(environment, tags, keyringPassphrase string, username string, password string, k keyring.Keyring) error {
	// Enter keyring passphrase:

	// Check if provided keyring pw is correct, since it will be used for multiple commands
	// Check if publish command credentials are available in keyring and correct as stdin will not be availale in goroutine
	artifactsRepositoryDomain := "https://repositories.skilld.cloud"
	var accessibilityCode int
	if isURLAccessible("http://repositories.interaction.svc.skilld:8081", &accessibilityCode) {
		artifactsRepositoryDomain = "http://repositories.interaction.svc.skilld:8081"
	}
	cli.Println("Checking keyring...")
	_, save, err := getCredentials(artifactsRepositoryDomain, username, password, k)
	if err != nil {
		return err
	}
	// If publish command credentials were not found in keyring, we add them
	if save {
		err = k.Save() // TODO: If new keyring and passphrase is defined, use new passphrase right away in all commands > requires keyring lib update to get passphrase
		if err != nil {
			log.Err("Error during saving keyring file", err)
		}
	}
	fmt.Println()

	// Appending --keyring-passphrase to commands
	keyringCmd := func(command string, args ...string) *exec.Cmd {
		if keyringPassphrase != "" {
			args = append(args, "--keyring-passphrase", keyringPassphrase)
		}
		return exec.Command(command, args...)
	}

	log.Info(fmt.Sprintf("environment: %s", environment))
	log.Info(fmt.Sprintf("tags: %s", tags))
	log.Info(fmt.Sprintf("username: %s", username))

	// Commands executed sequentially

	fmt.Println()
	bumpCmd := exec.Command("plasmactl", "bump")
	bumpCmd.Stdout = os.Stdout
	bumpCmd.Stderr = os.Stderr
	bumpCmd.Stdin = os.Stdin
	cli.Println(sanitizeString(bumpCmd.String(), keyringPassphrase))
	_ = bumpCmd.Run()

	fmt.Println()
	composeCmd := keyringCmd("plasmactl", "compose", "--skip-not-versioned", "--conflicts-verbosity")
	composeCmd.Stdout = os.Stdout
	composeCmd.Stderr = os.Stderr
	composeCmd.Stdin = os.Stdin
	cli.Println(sanitizeString(composeCmd.String(), keyringPassphrase))
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
	syncCmd := exec.Command("plasmactl", "bump", "--sync")
	syncCmd.Stdout = os.Stdout
	syncCmd.Stderr = os.Stderr
	syncCmd.Stdin = os.Stdin
	cli.Println(sanitizeString(syncCmd.String(), keyringPassphrase))
	syncErr := syncCmd.Run()
	if syncErr != nil {
		if exitErr, ok := syncErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		} else {
			fmt.Println("Error:", syncErr)
			os.Exit(1)
		}
	}

	// Commands executed in parallel

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
		defer wg.Done()

		packageCmd := exec.Command("plasmactl", "package")
		packageCmd.Stdout = &packageStdOut
		packageCmd.Stderr = &packageStdErr
		//publishCmd.Stdin = os.Stdin // Any interaction will prevent waitgroup to finish and thus stuck before print of stdout
		cli.Println(sanitizeString(packageCmd.String(), keyringPassphrase))
		packageErr = packageCmd.Run()
		if packageErr != nil {
			return
		}

		publishCmd := keyringCmd("plasmactl", "publish")
		publishCmd.Stdout = &publishStdOut
		publishCmd.Stderr = &publishStdErr
		//publishCmd.Stdin = os.Stdin // Any interaction will prevent waitgroup to finish and thus stuck before print of stdout
		//cli.Println(sanitizeString(publishCmd.String(), keyringPassphrase)) // TODO: Debug why it appears in deploy command stdin
		publishErr = publishCmd.Run()
		if publishErr != nil {
			return
		}
	}(wg)

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		deployCmd := exec.Command("plasmactl", "platform:deploy", environment, tags)
		//deployCmd := keyringCmd("plasmactl", "deploy", environment, tags) // TODO: Use after https://projects.skilld.cloud/skilld/pla-plasmactl/-/issues/67
		deployCmd.Stdout = os.Stdout
		deployCmd.Stderr = os.Stderr
		deployCmd.Stdin = os.Stdin
		cli.Println(sanitizeString(deployCmd.String(), keyringPassphrase))
		deployErr := deployCmd.Run()
		if deployErr != nil {
			if exitErr, ok := deployErr.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			} else {
				fmt.Println("Error:", deployErr)
				os.Exit(1)
			}
		}
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

func getCredentials(url, username, password string, k keyring.Keyring) (keyring.CredentialsItem, bool, error) {
	ci, err := k.GetForURL(url)
	save := false
	if len(ci.URL) != 0 && len(ci.Username) != 0 && len(ci.Password) != 0 {
		cli.Println("Keyring was unlocked successfully: publish credentials were found")
	}
	if err != nil {
		if errors.Is(err, keyring.ErrEmptyPass) {
			return ci, false, err
		} else if errors.Is(err, keyring.ErrNotFound) {
			cli.Println("Keyring was unlocked or created successfully: publish credentials were not found")
		} else if !errors.Is(err, keyring.ErrNotFound) {
			log.Debug("%s", err)
			return ci, false, errors.New("the keyring is malformed or wrong passphrase provided")
		}
		ci = keyring.CredentialsItem{}
		ci.URL = url
		ci.Username = username
		ci.Password = password
		if ci.Username == "" || ci.Password == "" {
			if ci.URL != "" {
				cli.Println("Please add login and password for URL - %s", ci.URL)
			}
			err = keyring.RequestCredentialsFromTty(&ci)
			if err != nil {
				return ci, false, err
			}
		}

		err = k.AddItem(ci)
		if err != nil {
			return ci, false, err
		}

		save = true
	}

	return ci, save, nil
}

func isURLAccessible(url string, code *int) bool {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}

	defer resp.Body.Close()
	*code = resp.StatusCode
	return resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices
}

func sanitizeString(command string, passphrase string) string {
	if passphrase != "" {
		return strings.ReplaceAll(command, passphrase, "[masked]")
	} else {
		return command
	}
}
