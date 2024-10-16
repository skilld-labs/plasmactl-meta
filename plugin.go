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

var tplAddCredentials = "execute '%s login --url=%s' to add credentials to keyring" //nolint G101

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
	ci                bool
}

// CobraAddCommands implements launchr.CobraPlugin interface to provide meta functionality.
func (p *Plugin) CobraAddCommands(rootCmd *cobra.Command) error {
	options := metaOptions{}

	metaCmd := &cobra.Command{
		Use:     "meta [flags] environment tags",
		Short:   "Executes bump + compose + sync + package + publish + deploy",
		Aliases: []string{"deliver"},
		Args:    cobra.MatchAll(cobra.ExactArgs(2), cobra.OnlyValidArgs),
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
	metaCmd.Flags().BoolVar(&options.ci, "ci", false, "Execute all commands and deploy in CI")

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
	// Retrieve current binary name from args to use in consequent commands.
	plasmaBinary := os.Args[0]

	var commonArgs []string
	verbosity := ""
	if options.verboseCount > 0 {
		verbosity = "-" + strings.Repeat("v", options.verboseCount)
		commonArgs = append(commonArgs, verbosity)
		log.Debug("verbosity set as %q", verbosity)
	}

	log.Info(fmt.Sprintf("environment: %s", environment))
	log.Info(fmt.Sprintf("tags: %s", tags))

	var username string
	var password string

	if options.ci {
		cli.Println("Starting CI build")

		gitlabDomain := "https://projects.skilld.cloud"
		log.Info("Getting %s credentials from keyring", gitlabDomain)
		ci, save, err := getCredentials(gitlabDomain, username, password, k)
		if err != nil {
			return err
		}
		log.Info("URL: %s", ci.URL)
		log.Info("Username: %s", ci.Username)

		username := ci.Username
		password := ci.Password

		comparisonRef := ""
		if options.override != "" {
			comparisonRef = options.override
			log.Info("Comparison artifact override: %s", comparisonRef)
		}

		// Get OAuth token
		accessToken, err := getOAuthToken(gitlabDomain, username, password)
		if err != nil {
			log.Fatal("Failed to get OAuth token: %v", err)
		}

		// Save gitlab credentials to keyiring once we are sure that they are correct (after 1st successful api reuuest)
		if save {
			err = k.Save()
			log.Debug("saving %s credentials to keyring", gitlabDomain)
			if err != nil {
				log.Err("Error during saving keyring file", err)
			}
		}

		// Get branch name
		branchName, err := getBranchName()
		if err != nil {
			log.Fatal("Failed to get branch name: %v", err)
		}

		// Get repo name
		repoName, err := getRepoName()
		if err != nil {
			log.Fatal("Failed to get repo name: %v", err)
		}

		// Get project ID
		projectID, err := getProjectID(gitlabDomain, username, password, accessToken, repoName)
		if err != nil {
			log.Fatal("Failed to get ID of project '%s': %v", repoName, err)
		}

		// Trigger pipeline
		pipelineID, err := triggerPipeline(gitlabDomain, username, password, accessToken, projectID, branchName, environment, tags, comparisonRef)
		if err != nil {
			log.Fatal("Failed to trigger pipeline: %v", err)
		}

		// Get all jobs in the pipeline
		jobs, err := getJobsInPipeline(gitlabDomain, username, password, accessToken, projectID, pipelineID)
		if err != nil {
			log.Fatal("Failed to retrieve jobs in pipeline: %v", err)
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
			log.Fatal("No %s job found in pipeline", targetJobName)
		}

		// Trigger the manual job
		err = triggerManualJob(gitlabDomain, username, password, accessToken, projectID, targetJobID, pipelineID)
		if err != nil {
			log.Fatal("Failed to trigger manual job: %v", err)
		}

	} else {
		cli.Println("Starting local build")

		// Check if provided keyring pw is correct, since it will be used for multiple commands
		// Check if publish command credentials are available in keyring and correct as stdin will not be available in goroutine
		artifactsRepositoryDomain := "https://repositories.skilld.cloud"
		var accessibilityCode int
		if isURLAccessible("http://repositories.interaction.svc.skilld:8081", &accessibilityCode) {
			artifactsRepositoryDomain = "http://repositories.interaction.svc.skilld:8081"
		}
		cli.Println("Checking keyring...")
		keyringEntryName := "Artifacts repository"
		err := validateCredentials(artifactsRepositoryDomain, plasmaBinary, k, keyringEntryName)
		if err != nil {
			return err
		}

		// Appending --keyring-passphrase to commands
		keyringCmd := func(command string, args ...string) *exec.Cmd {
			if options.keyringPassphrase != "" {
				args = append(args, "--keyring-passphrase", options.keyringPassphrase)
			}

			return exec.Command(command, args...)
		}

		// Commands executed sequentially

		fmt.Println()
		bumpArgs := []string{"bump"}
		if options.last {
			bumpArgs = append(bumpArgs, "--last")
		}
		bumpArgs = append(bumpArgs, commonArgs...)
		bumpCmd := exec.Command(plasmaBinary, bumpArgs...) //nolint G204
		bumpCmd.Stdout = os.Stdout
		bumpCmd.Stderr = os.Stderr
		bumpCmd.Stdin = os.Stdin
		cli.Println(sanitizeString(bumpCmd.String(), options.keyringPassphrase))
		_ = bumpCmd.Run() //nolint

		fmt.Println()
		composeArgs := []string{"compose", "--conflicts-verbosity"}
		if options.clean {
			composeArgs = append(composeArgs, "--clean")
		}
		composeArgs = append(composeArgs, commonArgs...)
		composeCmd := keyringCmd(plasmaBinary, composeArgs...)
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
		syncCmd := keyringCmd(plasmaBinary, bumpSyncArgs...)
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
			packageCmd := exec.Command(plasmaBinary, packageCmdArgs...) //nolint G204
			packageCmd.Stdout = &packageStdOut
			packageCmd.Stderr = &packageStdErr
			// publishCmd.Stdin = os.Stdin // Any interaction will prevent waitgroup to finish and thus stuck before print of stdout
			// cli.Println(sanitizeString(packageCmd.String(), options.keyringPassphrase)) // TODO: Find a way to prevent it to fill deploy stdin
			packageErr = packageCmd.Run()
			if packageErr != nil {
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

			deployCmd := keyringCmd(plasmaBinary, deployCmdArgs...)
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

func validateCredentials(url, plasmaBinary string, k keyring.Keyring, keyringEntryName string) error {
	if !k.Exists() {
		cli.Println("Keyring doesn't exist")
		return fmt.Errorf(tplAddCredentials, plasmaBinary, url)
	}

	ci, err := k.GetForURL(url)
	if len(ci.URL) != 0 && len(ci.Username) != 0 && len(ci.Password) != 0 {
		cli.Println("Keyring was unlocked successfully: %s credentials were found", keyringEntryName)
	}
	if err != nil {
		if errors.Is(err, keyring.ErrEmptyPass) {
			return err
		} else if errors.Is(err, keyring.ErrNotFound) {
			cli.Println("Keyring was unlocked successfully: %s credentials were not found", keyringEntryName)
			return fmt.Errorf(tplAddCredentials, plasmaBinary, url)
		} else if !errors.Is(err, keyring.ErrNotFound) {
			log.Debug("%s", err)
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
	}

	return command
}
