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

	"github.com/launchrctl/keyring"
	"github.com/launchrctl/launchr"
	"github.com/spf13/cobra"
)

func init() {
	launchr.RegisterPlugin(&Plugin{})
}

var tplAddCredentials = "execute '%s login --url=%s' to add credentials to keyring" //nolint G101

// Plugin is launchr plugin providing meta action.
type Plugin struct {
	k   keyring.Keyring
	app launchr.App
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
	p.app = app
	return nil
}

type metaOptions struct {
	verboseCount      int
	keyringPassphrase string
	override          string
	clean             bool
	last              bool
	ci                bool
}

// CobraAddCommands implements launchr.CobraPlugin interface to provide meta functionality.
func (p *Plugin) CobraAddCommands(rootCmd *launchr.Command) error {
	options := metaOptions{}

	metaCmd := &launchr.Command{
		Use:     "meta [flags] environment tags",
		Short:   "Executes bump + compose + sync + package + publish + deploy",
		Aliases: []string{"deliver"},
		Args:    cobra.MatchAll(cobra.ExactArgs(2), cobra.OnlyValidArgs),
		RunE: func(cmd *launchr.Command, args []string) error {
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

			return p.meta(args[0], args[1], options)
		},
	}
	metaCmd.SetArgs([]string{"environment", "tags"})
	metaCmd.Flags().StringVar(&options.override, "override", "", "Bump --sync override option")
	metaCmd.Flags().BoolVar(&options.clean, "clean", false, "Clean flag for compose command")
	metaCmd.Flags().BoolVar(&options.last, "last", false, "Last flag for bump command")
	metaCmd.Flags().BoolVar(&options.ci, "ci", false, "Execute all commands and deploy in CI")

	rootCmd.AddCommand(metaCmd)
	return nil
}

func ensureKeyringPassphraseSet(cmd *launchr.Command, options *metaOptions) error {
	keyringPassphrase, err := cmd.Flags().GetString("keyring-passphrase")
	if err != nil {
		return fmt.Errorf("error while getting keyring-passphrase option value: %w", err)
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

func (p *Plugin) meta(environment, tags string, options metaOptions) error {
	// Retrieve current binary name from args to use in consequent commands.
	plasmaBinary := os.Args[0]
	streams := p.app.Streams()

	var commonArgs []string
	verbosity := ""
	if options.verboseCount > 0 {
		verbosity = "-" + strings.Repeat("v", options.verboseCount)
		commonArgs = append(commonArgs, verbosity)
		launchr.Log().Debug("verbosity level", "level", verbosity)
	}

	launchr.Log().Info("arguments", "environment", environment, "tags", tags)

	var username string
	var password string

	if options.ci {
		launchr.Term().Info().Println("Starting CI build")

		gitlabDomain := "https://projects.skilld.cloud"
		launchr.Term().Info().Printfln("Getting %s credentials from keyring", gitlabDomain)
		ci, save, err := getCredentials(gitlabDomain, username, password, p.k)
		if err != nil {
			return err
		}
		launchr.Term().Printfln("URL: %s", ci.URL)
		launchr.Term().Printfln("Username: %s", ci.Username)

		username := ci.Username
		password := ci.Password

		comparisonRef := ""
		if options.override != "" {
			comparisonRef = options.override
			launchr.Term().Printfln("Comparison artifact override: %s", comparisonRef)
		}

		// Get OAuth token
		accessToken, err := getOAuthToken(gitlabDomain, username, password)
		if err != nil {
			return fmt.Errorf("failed to get OAuth token: %w", err)
		}

		// Save gitlab credentials to keyiring once we are sure that they are correct (after 1st successful api reuuest)
		if save {
			err = p.k.Save()
			launchr.Log().Debug("saving credentials to keyring", "url", gitlabDomain)
			if err != nil {
				launchr.Log().Error("error during saving keyring file", "error", err)
			}
		}

		// Get branch name
		branchName, err := getBranchName()
		if err != nil {
			return fmt.Errorf("failed to get branch name: %w", err)
		}

		// Get repo name
		repoName, err := getRepoName()
		if err != nil {
			return fmt.Errorf("failed to get repo name: %w", err)
		}

		// Get project ID
		projectID, err := getProjectID(gitlabDomain, username, password, accessToken, repoName)
		if err != nil {
			return fmt.Errorf("failed to get ID of project %q: %w", repoName, err)
		}

		// Trigger pipeline
		pipelineID, err := triggerPipeline(gitlabDomain, username, password, accessToken, projectID, branchName, environment, tags, comparisonRef)
		if err != nil {
			return fmt.Errorf("failed to trigger pipeline: %w", err)
		}

		// Get all jobs in the pipeline
		jobs, err := getJobsInPipeline(gitlabDomain, username, password, accessToken, projectID, pipelineID)
		if err != nil {
			return fmt.Errorf("failed to retrieve jobs in pipeline: %w", err)
		}

		// Find the target job ID
		var targetJobID int
		for _, job := range jobs {
			if job.Name == targetJobName {
				targetJobID = job.ID
				break
			}
		}
		if targetJobID == 0 {
			return fmt.Errorf("no %s job found in pipeline", targetJobName)
		}

		// Trigger the manual job
		err = triggerManualJob(gitlabDomain, username, password, accessToken, projectID, targetJobID, pipelineID)
		if err != nil {
			return fmt.Errorf("failed to trigger manual job: %w", err)
		}

	} else {
		launchr.Term().Info().Println("Starting local build")
		println("1")
		// Check if provided keyring pw is correct, since it will be used for multiple commands
		// Check if publish command credentials are available in keyring and correct as stdin will not be available in goroutine
		artifactsRepositoryDomain := "https://repositories.skilld.cloud"
		var accessibilityCode int
		if isURLAccessible("http://repositories.interaction.svc.skilld:8081", &accessibilityCode) {
			artifactsRepositoryDomain = "http://repositories.interaction.svc.skilld:8081"
		}
		launchr.Term().Println("Checking keyring...")
		keyringEntryName := "Artifacts repository"
		err := validateCredentials(artifactsRepositoryDomain, plasmaBinary, p.k, keyringEntryName)
		if err != nil {
			return err
		}
		println("2")

		// Appending --keyring-passphrase to commands
		keyringCmd := func(command string, args ...string) *exec.Cmd {
			if options.keyringPassphrase != "" {
				args = append(args, "--keyring-passphrase", options.keyringPassphrase)
			}

			return exec.Command(command, args...)
		}

		// Commands executed sequentially

		println("3")
		launchr.Term().Println()
		bumpArgs := []string{"bump"}
		if options.last {
			bumpArgs = append(bumpArgs, "--last")
		}
		println("4")
		bumpArgs = append(bumpArgs, commonArgs...)
		bumpCmd := exec.Command(plasmaBinary, bumpArgs...) //nolint G204
		bumpCmd.Stdout = streams.Out()
		bumpCmd.Stderr = streams.Err()
		bumpCmd.Stdin = streams.In()
		println("5")
		launchr.Term().Println(sanitizeString(bumpCmd.String(), options.keyringPassphrase))
		_ = bumpCmd.Run() //nolint

		println("6")
		//launchr.Term().Println()
		fmt.Println()
		composeArgs := []string{"compose", "--skip-not-versioned", "--conflicts-verbosity"}
		println("7")
		if options.clean {
			composeArgs = append(composeArgs, "--clean")
		}
		println("8")
		composeArgs = append(composeArgs, commonArgs...)
		composeCmd := keyringCmd(plasmaBinary, composeArgs...)
		composeCmd.Stdout = streams.Out()
		composeCmd.Stderr = streams.Err()
		composeCmd.Stdin = streams.In()
		println("9")
		launchr.Term().Println(sanitizeString(composeCmd.String(), options.keyringPassphrase))
		composeErr := composeCmd.Run()
		println("10")
		if composeErr != nil {
			return handleCmdErr(composeErr, "compose error")
		}

		println("11")
		launchr.Term().Println()
		bumpSyncArgs := []string{"bump", "--sync"}
		if options.override != "" {
			bumpSyncArgs = append(bumpSyncArgs, "--override", options.override)
		}
		bumpSyncArgs = append(bumpSyncArgs, commonArgs...)
		syncCmd := keyringCmd(plasmaBinary, bumpSyncArgs...)
		syncCmd.Stdout = streams.Out()
		syncCmd.Stderr = streams.Err()
		syncCmd.Stdin = streams.In()
		launchr.Term().Println(sanitizeString(syncCmd.String(), options.keyringPassphrase))
		syncErr := syncCmd.Run()
		if syncErr != nil {
			return handleCmdErr(syncErr, "sync error")
		}

		// Commands executed in parallel

		var packageStdOut bytes.Buffer
		var packageStdErr bytes.Buffer
		var packageErr error

		var publishStdOut bytes.Buffer
		var publishStdErr bytes.Buffer
		var publishErr error

		launchr.Term().Println()
		wg := &sync.WaitGroup{}
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer wg.Done()
			packageCmdArgs := []string{"package"}
			packageCmdArgs = append(packageCmdArgs, commonArgs...)
			packageCmd := exec.Command(plasmaBinary, packageCmdArgs...) //nolint G204
			packageCmd.Stdout = &packageStdOut
			packageCmd.Stderr = &packageStdErr
			// publishCmd.Stdin = os.Stdin // Any interaction will prevent waitgroup to finish and thus stuck before print of stdout
			// cli.Println(sanitizeString(packageCmd.String(), options.keyringPassphrase)) // TODO: Find a way to prevent it to fill deploy stdin
			packageErr = packageCmd.Run()
			if packageErr != nil {
				publishErr = handleCmdErr(packageErr, "package error")
				return
			}

			publishCmdArgs := []string{"publish"}
			publishCmdArgs = append(publishCmdArgs, commonArgs...)
			publishCmd := keyringCmd(plasmaBinary, publishCmdArgs...)
			publishCmd.Stdout = &publishStdOut
			publishCmd.Stderr = &publishStdErr
			// publishCmd.Stdin = os.Stdin // Any interaction will prevent waitgroup to finish and thus stuck before print of stdout
			// cli.Println(sanitizeString(publishCmd.String(), keyringPassphrase)) // TODO: Debug why it appears during deploy command stdout
			publishErr = publishCmd.Run()
			if publishErr != nil {
				publishErr = handleCmdErr(publishErr, "publish error")
				return
			}
		}(wg)

		var deployErr error
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer wg.Done()
			deployCmdArgs := []string{"platform:deploy"}
			deployCmdArgs = append(deployCmdArgs, environment)
			deployCmdArgs = append(deployCmdArgs, tags)
			if verbosity != "" {
				deployCmdArgs = append(deployCmdArgs, "--debug")
			}

			deployCmd := keyringCmd(plasmaBinary, deployCmdArgs...)
			deployCmd.Stdout = streams.Out()
			deployCmd.Stderr = streams.Err()
			deployCmd.Stdin = streams.In()
			launchr.Term().Println(sanitizeString(deployCmd.String(), options.keyringPassphrase))
			deployErr = deployCmd.Run()
			if deployErr != nil {
				deployErr = handleCmdErr(deployErr, "deploy error")
				return
			}
		}(wg)
		wg.Wait()

		if packageStdOut.Len() > 0 {
			launchr.Term().Println()
			launchr.Term().Println("package stdout:")
			launchr.Term().Println(packageStdOut.String())
		}
		if packageStdErr.Len() > 0 {
			launchr.Term().Println("package stderr:")
			launchr.Term().Println(packageStdErr.String())
		}
		if publishStdOut.Len() > 0 {
			launchr.Term().Println()
			launchr.Term().Println("publish stdout:")
			launchr.Term().Println(publishStdOut.String())
		}
		if publishStdErr.Len() > 0 {
			launchr.Term().Println("publish stderr:")
			launchr.Term().Println(publishStdErr.String())
		}

		// Return all error messages, the first error code will be used as a result.
		errJoin := errors.Join(packageErr, publishErr, deployErr)
		if errJoin != nil {
			return errJoin
		}

	}
	return nil
}

func handleCmdErr(cmdErr error, msg string) error {
	var exitErr *exec.ExitError
	if errors.As(cmdErr, &exitErr) {
		return launchr.NewExitError(exitErr.ExitCode(), msg)
	}

	return cmdErr
}

func validateCredentials(url, plasmaBinary string, k keyring.Keyring, keyringEntryName string) error {
	if !k.Exists() {
		launchr.Term().Error().Println("Keyring doesn't exist")
		return fmt.Errorf(tplAddCredentials, plasmaBinary, url)
	}

	ci, err := k.GetForURL(url)
	if len(ci.URL) != 0 && len(ci.Username) != 0 && len(ci.Password) != 0 {
		launchr.Term().Success().Println("Keyring was unlocked successfully: %s credentials were found", keyringEntryName)
	}
	if err != nil {
		if errors.Is(err, keyring.ErrEmptyPass) {
			return err
		} else if errors.Is(err, keyring.ErrNotFound) {
			launchr.Term().Success().Println("Keyring was unlocked successfully: %s credentials were not found", keyringEntryName)
			return fmt.Errorf(tplAddCredentials, plasmaBinary, url)
		} else if !errors.Is(err, keyring.ErrNotFound) {
			launchr.Log().Error("error", "error", err)
			return errors.New("the keyring is malformed or wrong passphrase provided")
		}
	}

	return nil
}

func getCredentials(url, username, password string, k keyring.Keyring) (keyring.CredentialsItem, bool, error) {
	ci, err := k.GetForURL(url)
	save := false
	if err != nil {
		if errors.Is(err, keyring.ErrEmptyPass) {
			return ci, false, err
		} else if !errors.Is(err, keyring.ErrNotFound) {
			launchr.Log().Error("error", "error", err)
			return ci, false, errors.New("the keyring is malformed or wrong passphrase provided")
		}
		ci = keyring.CredentialsItem{}
		ci.URL = url
		ci.Username = username
		ci.Password = password
		if ci.Username == "" || ci.Password == "" {
			if ci.URL != "" {
				launchr.Term().Info().Printfln("Please add login and password for URL - %s", ci.URL)
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
	}

	return command
}
