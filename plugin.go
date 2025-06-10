// Package plasmactlmeta implements meta launchr plugin
package plasmactlmeta

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net/http"

	"github.com/launchrctl/keyring"
	"github.com/launchrctl/launchr"
	"github.com/launchrctl/launchr/pkg/action"
)

//go:embed action.yaml
var actionYaml []byte

func init() {
	launchr.RegisterPlugin(&Plugin{})
}

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
	gitlabDomain       string
	streams            launchr.Streams
	persistent         action.InputParams
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
			gitlabDomain:       input.Opt("gitlab-domain").(string),
			streams:            a.Input().Streams(),
			persistent:         a.Input().GroupFlags(p.m.GetPersistentFlags().GetName()),
		}

		meta := newMetaAction(a, p.k, p.m)
		return meta.run(ctx, env, tags, options)
	}))
	return []*action.Action{a}, nil
}

type metaAction struct {
	action.WithLogger
	action.WithTerm

	k  keyring.Keyring
	m  action.Manager
	g  *gitMeta
	ci *continuousIntegration
}

func newMetaAction(a *action.Action, k keyring.Keyring, m action.Manager) *metaAction {
	log := launchr.Log()
	if rt, ok := a.Runtime().(action.RuntimeLoggerAware); ok {
		log = rt.LogWith()
	}

	term := launchr.Term()
	if rt, ok := a.Runtime().(action.RuntimeTermAware); ok {
		term = rt.Term()
	}

	meta := &metaAction{k: k, m: m}
	meta.SetLogger(log)
	meta.SetTerm(term)

	meta.g = &gitMeta{WithLogger: meta.WithLogger, WithTerm: meta.WithTerm}
	meta.ci = &continuousIntegration{WithLogger: meta.WithLogger, WithTerm: meta.WithTerm}
	return meta
}

func (ma *metaAction) run(ctx context.Context, environment, tags string, options metaOptions) error {
	if options.ci {
		ma.Term().Info().Println("--ci option is deprecated: builds are now done by default in CI")
	}

	ma.Log().Info("arguments", "environment", environment, "tags", tags)

	ansibleDebug := options.debug
	if ansibleDebug {
		ma.Term().Info().Printfln("Ansible debug mode: %t", ansibleDebug)
	}

	var username, password string

	// Commit unversioned changes if any
	err := ma.g.commitChangesIfAny()
	if err != nil {
		return fmt.Errorf("commit error: %w", err)
	}

	// Execute bump
	if !options.skipBump {
		err = ma.executeAction(ctx, "bump", nil, action.InputParams{
			"last": options.last,
		},
			options.persistent, options.streams)
		if err != nil {
			return fmt.Errorf("bump error: %w", err)
		}
	} else {
		ma.Term().Info().Println("--skip-bump option detected: Skipping bump execution")
	}
	ma.Term().Printf("\n")

	if options.local {
		ma.Term().Info().Println("Starting local build")

		// Commands executed sequentially
		err = ma.executeAction(ctx, "compose", nil, action.InputParams{
			"skip-not-versioned":  true,
			"conflicts-verbosity": options.conflictsVerbosity,
			"clean":               options.clean,
		}, options.persistent, options.streams)
		if err != nil {
			return fmt.Errorf("compose error: %w", err)
		}

		ma.Term().Println()
		err = ma.executeAction(ctx, "bump", nil, action.InputParams{
			"sync": true,
		}, options.persistent, options.streams)
		if err != nil {
			return fmt.Errorf("sync error: %w", err)
		}

		err = ma.executeAction(ctx, "platform:deploy", action.InputParams{
			"environment": environment,
			"tags":        tags,
		}, action.InputParams{
			"debug": options.debug,
		}, options.persistent, options.streams)
		if err != nil {
			return fmt.Errorf("deploy error: %w", err)
		}

	} else {
		ma.Term().Info().Println("Starting CI build (now default behavior)")

		// Push branch if it does not exist on remote
		if err := ma.g.pushBranchIfNotRemote(); err != nil {
			return err
		}

		// Push any un-pushed commits
		if err := ma.g.pushCommitsIfAny(); err != nil {
			return err
		}

		gitlabDomain := options.gitlabDomain
		if gitlabDomain == "" {
			return fmt.Errorf("gitlab-domain is empty: pass it as option or local config")
		}
		ma.Term().Info().Printfln("Getting user credentials for %s from keyring", gitlabDomain)
		ci, save, err := ma.getCredentials(gitlabDomain, username, password)
		if err != nil {
			return err
		}
		ma.Term().Printfln("URL: %s", ci.URL)
		ma.Term().Printfln("Username: %s", ci.Username)

		username = ci.Username
		password = ci.Password

		// Get Gitlab OAuth token
		gitlabAccessToken, err := ma.ci.getOAuthTokens(gitlabDomain, username, password)
		if err != nil {
			return fmt.Errorf("failed to get OAuth token: %w", err)
		}

		// Save gitlab credentials to keyring once API requests are successful
		if save {
			err = ma.k.Save()
			ma.Log().Debug("saving user credentials to keyring", "url", gitlabDomain)
			if err != nil {
				ma.Log().Error("error during saving keyring file", "error", err)
			}
		}

		// Get branch name
		branchName, err := ma.ci.getBranchName()
		if err != nil {
			return fmt.Errorf("failed to get branch name: %w", err)
		}

		// Get repo name
		repoName, err := ma.ci.getRepoName()
		if err != nil {
			return fmt.Errorf("failed to get repo name: %w", err)
		}

		// Get project ID
		projectID, err := ma.ci.getProjectID(gitlabDomain, gitlabAccessToken, repoName)
		if err != nil {
			return fmt.Errorf("failed to get ID of project %q: %w", repoName, err)
		}

		// Trigger pipeline
		pipelineID, err := ma.ci.triggerPipeline(gitlabDomain, gitlabAccessToken, projectID, branchName, environment, tags, ansibleDebug)
		if err != nil {
			return fmt.Errorf("failed to trigger pipeline: %w", err)
		}

		// Get all jobs in the pipeline
		jobs, err := ma.ci.getJobsInPipeline(gitlabDomain, gitlabAccessToken, projectID, pipelineID)
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
		err = ma.ci.triggerManualJob(gitlabDomain, gitlabAccessToken, projectID, targetJobID, pipelineID)
		if err != nil {
			return fmt.Errorf("failed to trigger manual job: %w", err)
		}
	}
	return nil
}

func (ma *metaAction) executeAction(ctx context.Context, id string, args, opts, persistent action.InputParams, streams launchr.Streams) error {
	a, ok := ma.m.Get(id)
	if !ok {
		return fmt.Errorf("action %q was not found", id)
	}

	persistentKey := ma.m.GetPersistentFlags().GetName()
	input := action.NewInput(a, args, opts, streams)
	for k, v := range persistent {
		input.SetFlagInGroup(persistentKey, k, v)
	}

	err := ma.m.ValidateInput(a, input)
	if err != nil {
		return fmt.Errorf("failed to validate input for action %q: %w", id, err)
	}

	err = a.SetInput(input)
	if err != nil {
		return fmt.Errorf("failed to set input for action %q: %w", id, err)
	}

	ma.m.Decorate(a)
	err = a.Execute(ctx)
	if err != nil {
		return fmt.Errorf("error executing action %q: %w", id, err)
	}
	return nil
}

func (ma *metaAction) getCredentials(url, username, password string) (keyring.CredentialsItem, bool, error) {
	ci, err := ma.k.GetForURL(url)
	save := false
	if err != nil {
		if errors.Is(err, keyring.ErrEmptyPass) {
			return ci, false, err
		} else if !errors.Is(err, keyring.ErrNotFound) {
			ma.Log().Error("error", "error", err)
			return ci, false, errors.New("the keyring is malformed or wrong passphrase provided")
		}
		ci = keyring.CredentialsItem{}
		ci.URL = url
		ci.Username = username
		ci.Password = password
		if ci.Username == "" || ci.Password == "" {
			if ci.URL != "" {
				ma.Term().Info().Printfln("Please add login and password for %s", ci.URL)
			}
			err = keyring.RequestCredentialsFromTty(&ci)
			if err != nil {
				return ci, false, err
			}
		}

		err = ma.k.AddItem(ci)
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
