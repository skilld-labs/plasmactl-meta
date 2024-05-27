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

var (
	errAddCredentials = errors.New("execute 'plasmactl login --url=https://repositories.skilld.cloud' to add credentials to keyring")
)

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

type metaOptions struct {
	verboseCount      int
	keyringPassphrase string
	override          string
	clean             bool
	last              bool
}

// CobraAddCommands implements launchr.CobraPlugin interface to provide meta functionality.
func (p *Plugin) CobraAddCommands(rootCmd *cobra.Command) error {
	options := metaOptions{}

	var metaCmd = &cobra.Command{
		Use:   "meta [flags] environment tags",
		Short: "Executes bump + compose + sync + package + publish + deploy",
		Args:  cobra.MatchAll(cobra.ExactArgs(2), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Don't show usage help on a runtime error.
			cmd.SilenceUsage = true

			err := ensureKeyringPassphraseSet(cmd, &options)
			if err != nil {
				return err
			}

			verboseCount, err := cmd.Flags().GetCount("verbose")
			if err != nil {
				return err
			}
			options.verboseCount = verboseCount

			return meta(args[0], args[1], options, p.k)
		},
	}
	metaCmd.SetArgs([]string{"environment", "tags"})
	metaCmd.Flags().StringVar(&options.override, "override", "", "Bump --sync override option")
	metaCmd.Flags().BoolVar(&options.clean, "clean", false, "Clean flag for compose command")
	metaCmd.Flags().BoolVar(&options.last, "last", false, "Last flag for bump command")

	rootCmd.AddCommand(metaCmd)
	return nil
}

func ensureKeyringPassphraseSet(cmd *cobra.Command, options *metaOptions) error {
	keyringPassphrase, err := cmd.Flags().GetString("keyring-passphrase")
	if err != nil {
		log.Fatal("error while getting keyringPassphrase option value: ", err)
	}

	if keyringPassphrase == "" {
		askPass := keyring.AskPassWithTerminal{}
		var passphrase string
		var errGet error

		passphrase, errGet = askPass.GetPass()
		if errGet != nil {
			return errGet
		}

		keyringPassphrase = passphrase
		err = cmd.Flags().Set("keyring-passphrase", keyringPassphrase)
		if err != nil {
			return err
		}
	}

	options.keyringPassphrase = keyringPassphrase

	return nil
}

func meta(environment, tags string, options metaOptions, k keyring.Keyring) error {
	// Check if provided keyring pw is correct, since it will be used for multiple commands
	// Check if publish command credentials are available in keyring and correct as stdin will not be available in goroutine
	artifactsRepositoryDomain := "https://repositories.skilld.cloud"
	var accessibilityCode int
	if isURLAccessible("http://repositories.interaction.svc.skilld:8081", &accessibilityCode) {
		artifactsRepositoryDomain = "http://repositories.interaction.svc.skilld:8081"
	}
	cli.Println("Checking keyring...")
	err := validateCredentials(artifactsRepositoryDomain, k)
	if err != nil {
		return err
	}

	var commonArgs []string
	verbosity := ""
	if options.verboseCount > 0 {
		verbosity = "-" + strings.Repeat("v", options.verboseCount)
		commonArgs = append(commonArgs, verbosity)
		log.Debug("verbosity set as %q", verbosity)
	}

	// Appending --keyring-passphrase to commands
	keyringCmd := func(command string, args ...string) *exec.Cmd {
		if options.keyringPassphrase != "" {
			args = append(args, "--keyring-passphrase", options.keyringPassphrase)
		}

		return exec.Command(command, args...)
	}

	log.Info(fmt.Sprintf("environment: %s", environment))
	log.Info(fmt.Sprintf("tags: %s", tags))

	// Commands executed sequentially

	fmt.Println()
	bumpArgs := []string{"bump"}
	if options.last {
		bumpArgs = append(bumpArgs, "--last")
	}
	bumpArgs = append(bumpArgs, commonArgs...)
	bumpCmd := exec.Command("plasmactl", bumpArgs...)
	bumpCmd.Stdout = os.Stdout
	bumpCmd.Stderr = os.Stderr
	bumpCmd.Stdin = os.Stdin
	cli.Println(sanitizeString(bumpCmd.String(), options.keyringPassphrase))
	_ = bumpCmd.Run()

	fmt.Println()
	composeArgs := []string{"compose", "--skip-not-versioned", "--conflicts-verbosity"}
	if options.clean {
		composeArgs = append(composeArgs, "--clean")
	}
	composeArgs = append(composeArgs, commonArgs...)
	composeCmd := keyringCmd("plasmactl", composeArgs...)
	composeCmd.Stdout = os.Stdout
	composeCmd.Stderr = os.Stderr
	composeCmd.Stdin = os.Stdin
	cli.Println(sanitizeString(composeCmd.String(), options.keyringPassphrase))
	composeErr := composeCmd.Run()
	if composeErr != nil {
		handleCmdErr(composeErr)
	}

	fmt.Println()
	bumpSyncArgs := []string{"bump", "--sync"}
	if options.override != "" {
		bumpSyncArgs = append(bumpSyncArgs, "--override", options.override)
	}
	bumpSyncArgs = append(bumpSyncArgs, commonArgs...)
	syncCmd := keyringCmd("plasmactl", bumpSyncArgs...)
	syncCmd.Stdout = os.Stdout
	syncCmd.Stderr = os.Stderr
	syncCmd.Stdin = os.Stdin
	cli.Println(sanitizeString(syncCmd.String(), options.keyringPassphrase))
	syncErr := syncCmd.Run()
	if syncErr != nil {
		handleCmdErr(syncErr)
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
		packageCmdArgs := []string{"package"}
		packageCmdArgs = append(packageCmdArgs, commonArgs...)
		packageCmd := exec.Command("plasmactl", packageCmdArgs...)
		packageCmd.Stdout = &packageStdOut
		packageCmd.Stderr = &packageStdErr
		//publishCmd.Stdin = os.Stdin // Any interaction will prevent waitgroup to finish and thus stuck before print of stdout
		//cli.Println(sanitizeString(packageCmd.String(), options.keyringPassphrase)) // TODO: Find a way to prevent it to fill deploy stdin
		packageErr = packageCmd.Run()
		if packageErr != nil {
			return
		}

		publishCmdArgs := []string{"publish"}
		publishCmdArgs = append(publishCmdArgs, commonArgs...)
		publishCmd := keyringCmd("plasmactl", publishCmdArgs...)
		publishCmd.Stdout = &publishStdOut
		publishCmd.Stderr = &publishStdErr
		//publishCmd.Stdin = os.Stdin // Any interaction will prevent waitgroup to finish and thus stuck before print of stdout
		//cli.Println(sanitizeString(publishCmd.String(), keyringPassphrase)) // TODO: Debug why it appears during deploy command stdout
		publishErr = publishCmd.Run()
		if publishErr != nil {
			return
		}
	}(wg)

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		deployCmdArgs := []string{"platform:deploy"}
		deployCmdArgs = append(deployCmdArgs, environment)
		deployCmdArgs = append(deployCmdArgs, tags)
		if verbosity != "" {
			deployCmdArgs = append(deployCmdArgs, "--debug")
		}

		deployCmd := keyringCmd("plasmactl", deployCmdArgs...)
		deployCmd.Stdout = os.Stdout
		deployCmd.Stderr = os.Stderr
		deployCmd.Stdin = os.Stdin
		cli.Println(sanitizeString(deployCmd.String(), options.keyringPassphrase))
		deployErr := deployCmd.Run()
		if deployErr != nil {
			handleCmdErr(deployErr)
		}
	}(wg)
	wg.Wait()

	fmt.Println()
	fmt.Println(packageStdOut.String())
	fmt.Println(packageStdErr.String())
	if packageErr != nil {
		handleCmdErr(packageErr)
	}

	fmt.Println(publishStdOut.String())
	fmt.Println(publishStdErr.String())
	if publishErr != nil {
		handleCmdErr(publishErr)
	}

	return nil
}

func handleCmdErr(cmdErr error) {
	var exitErr *exec.ExitError
	if errors.As(cmdErr, &exitErr) {
		os.Exit(exitErr.ExitCode())
	}

	fmt.Println("Error:", cmdErr)
	os.Exit(1)
}

func validateCredentials(url string, k keyring.Keyring) error {
	if !k.Exists() {
		cli.Println("Keyring doesn't exist")
		return errAddCredentials
	}

	ci, err := k.GetForURL(url)
	if len(ci.URL) != 0 && len(ci.Username) != 0 && len(ci.Password) != 0 {
		cli.Println("Keyring was unlocked successfully: publish credentials were found")
	}
	if err != nil {
		if errors.Is(err, keyring.ErrEmptyPass) {
			return err
		} else if errors.Is(err, keyring.ErrNotFound) {
			cli.Println("Keyring was unlocked successfully: publish credentials were not found")
			return errAddCredentials
		} else if !errors.Is(err, keyring.ErrNotFound) {
			log.Debug("%s", err)
			return errors.New("the keyring is malformed or wrong passphrase provided")
		}
	}

	return nil
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
	}

	return command
}
