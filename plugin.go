// Package plasmactlmeta implements meta launchr plugin
package plasmactlmeta

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/launchrctl/keyring"
	"github.com/launchrctl/launchr"
	"github.com/launchrctl/launchr/pkg/action"
)

//go:embed action.yaml
var actionYaml []byte

func init() {
	launchr.RegisterPlugin(&Plugin{})
}

const (
	tplAddCredentials  = "execute '%s keyring:login --url=%s' to add credentials to keyring" //nolint:gosec
	gitlabDomain       = "https://projects.skilld.cloud"
	repoDomain         = "https://repositories.skilld.cloud"
	internalRepoDomain = "http://repositories.interaction.svc.skilld:8081"
)

// Plugin is launchr plugin providing meta action.
type Plugin struct {
	k   keyring.Keyring
	m   action.Manager
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
	app.GetService(&p.m)
	p.app = app
	return nil
}

type metaOptions struct {
	bin                string
	last               bool
	skipBump           bool
	ci                 bool
	local              bool
	clean              bool
	debug              bool
	conflictsVerbosity bool
}

// DiscoverActions implements [launchr.ActionDiscoveryPlugin] interface.
func (p *Plugin) DiscoverActions(_ context.Context) ([]*action.Action, error) {
	a := action.NewFromYAML("meta", actionYaml)
	a.SetRuntime(action.NewFnRuntime(func(ctx context.Context, a *action.Action) error {
		input := a.Input()
		env := input.Arg("environment").(string)
		tags := input.Arg("tags").(string)
		v := launchr.Version()
		options := metaOptions{
			bin:                v.Name,
			last:               input.Opt("last").(bool),
			skipBump:           input.Opt("skip-bump").(bool),
			ci:                 input.Opt("ci").(bool),
			local:              input.Opt("local").(bool),
			clean:              input.Opt("clean").(bool),
			debug:              input.Opt("debug").(bool),
			conflictsVerbosity: input.Opt("conflicts-verbosity").(bool),
		}

		return p.meta(ctx, env, tags, options)
	}))
	return []*action.Action{a}, nil
}

func (p *Plugin) meta(ctx context.Context, environment, tags string, options metaOptions) error {

	logLvl := launchr.Log().Level()
	println("logLvl")
	fmt.Println(logLvl)
	println("LogLevelDisabled")
	fmt.Println(launchr.LogLevelDisabled)
	println("XXXXXXXXXXXXX")

	if options.ci {
		launchr.Term().Info().Println("--ci option is deprecated: builds are now done by default in CI")
	}

	launchr.Log().Info("arguments", "environment", environment, "tags", tags)

	ansibleDebug := options.debug
	if ansibleDebug {
		launchr.Term().Info().Printfln("Ansible debug mode: %t", ansibleDebug)
	}

	var username string
	var password string

	// Commit unversioned changes if any
	err := commitChangesIfAny()
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	// Execute bump
	if !options.skipBump {
		err = p.executeAction(ctx, "bump", nil, action.InputParams{
			"last": options.last,
		})
		if err != nil {
			return fmt.Errorf("bump error: %w", err)
		}
	} else {
		launchr.Term().Info().Println("--skip-bump option detected: Skipping bump execution")
	}
	launchr.Term().Printf("\n")

	if options.local {
		launchr.Term().Info().Println("Starting local build")

		// Check if provided keyring pw is correct, since it will be used for multiple commands
		// Check if publish command credentials are available in keyring and correct as stdin will not be available in goroutine
		artifactsRepositoryDomain := repoDomain
		var accessibilityCode int
		if isURLAccessible(internalRepoDomain, &accessibilityCode) {
			artifactsRepositoryDomain = internalRepoDomain
		}
		launchr.Term().Println("Checking keyring...")
		keyringEntryName := "Artifacts repository"
		err := validateCredentials(artifactsRepositoryDomain, options.bin, p.k, keyringEntryName)
		if err != nil {
			return err
		}

		// Commands executed sequentially
		err = p.executeAction(ctx, "compose", nil, action.InputParams{
			"skip-not-versioned":  true,
			"conflicts-verbosity": options.conflictsVerbosity,
			"clean":               options.clean,
		})
		if err != nil {
			return fmt.Errorf("compose error: %w", err)
		}

		launchr.Term().Println()
		err = p.executeAction(ctx, "bump", nil, action.InputParams{
			"sync":          true,
			"show-progress": true,
		})
		if err != nil {
			return fmt.Errorf("sync error: %w", err)
		}

		// Commands executed in parallel
		var packageErr error
		var publishErr error

		launchr.Term().Println()
		wg := &sync.WaitGroup{}
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer wg.Done()
			packageErr = p.executeAction(ctx, "package", nil, nil)
			if packageErr != nil {
				return
			}

			publishErr = p.executeAction(ctx, "publish", nil, nil)
			if publishErr != nil {
				return
			}
		}(wg)

		var deployErr error
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer wg.Done()
			deployErr = p.executeAction(ctx, "platform:deploy",
				action.InputParams{
					"environment": environment,
					"tags":        tags,
				},
				action.InputParams{
					"debug": options.debug,
				},
			)
			if deployErr != nil {
				return
			}
		}(wg)
		wg.Wait()

		// Return all error messages, the first error code will be used as a result.
		errJoin := errors.Join(packageErr, publishErr, deployErr)
		if errJoin != nil {
			return errJoin
		}

	} else {
		launchr.Term().Info().Println("Starting CI build (now default behavior)")

		// Push un-pushed commits if any
		if err := pushBranchIfNotRemote(); err != nil {
			return err
		}

		// Push un-pushed commits if any
		if err := pushCommitsIfAny(); err != nil {
			return err
		}

		launchr.Term().Info().Printfln("Getting %s credentials from keyring", gitlabDomain)
		ci, save, err := getCredentials(gitlabDomain, username, password, p.k)
		if err != nil {
			return err
		}
		launchr.Term().Printfln("URL: %s", ci.URL)
		launchr.Term().Printfln("Username: %s", ci.Username)

		username = ci.Username
		password = ci.Password

		// Get OAuth token
		accessToken, err := getOAuthToken(gitlabDomain, username, password)
		if err != nil {
			return fmt.Errorf("failed to get OAuth token: %w", err)
		}

		// Save gitlab credentials to keyring once we are sure that they are correct (after 1st successful api request)
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
		pipelineID, err := triggerPipeline(gitlabDomain, username, password, accessToken, projectID, branchName, environment, tags, ansibleDebug)
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
	}
	return nil
}

func (p *Plugin) executeAction(ctx context.Context, id string, args action.InputParams, opts action.InputParams) error {
	a, ok := p.m.Get(id)
	if !ok {
		return fmt.Errorf("action %q was not found", id)
	}
	err := a.SetInput(action.NewInput(a, args, opts, p.app.Streams()))
	if err != nil {
		return fmt.Errorf("failed to set input for action %q: %w", id, err)
	}
	err = a.Execute(ctx)
	if err != nil {
		return fmt.Errorf("error executing action %q: %w", id, err)
	}
	return nil
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
