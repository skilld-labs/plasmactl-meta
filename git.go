package plasmactlmeta

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/launchrctl/launchr/pkg/action"
)

type gitMeta struct {
	action.WithLogger
	action.WithTerm
}

// Checks for uncommitted changes and creates a commit if any are found
func (g *gitMeta) commitChangesIfAny() error {
	// Open the existing repository
	repoPath, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}

	// Get the working tree
	worktree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	// Check for uncommitted changes
	status, err := worktree.Status()
	if err != nil {
		return fmt.Errorf("failed to get worktree status: %w", err)
	}

	if status.IsClean() {
		g.Log().Debug("No changes to commit.")
		return nil
	}

	g.Term().Info().Println("Unversioned changes detected. Creating commit...")

	// Add all changes to the index
	err = worktree.AddGlob(".")
	if err != nil {
		return fmt.Errorf("failed to stage changes: %w", err)
	}

	// Create a commit with the staged changes
	commitMessage := "Work in progress"
	commit, err := worktree.Commit(commitMessage, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Plasmactl",
			Email: "no-reply@skilld.cloud",
			When:  time.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to commit changes: %w", err)
	}

	// Print commit details
	obj, err := repo.CommitObject(commit)
	if err != nil {
		return fmt.Errorf("failed to retrieve commit object: %w", err)
	}

	//fmt.Printf("Created %s\n", obj.String())
	g.Term().Printf("Created commit %s\n", obj.Hash.String())
	g.Term().Printf("Author: %s <%s>\n", obj.Author.Name, obj.Author.Email)
	g.Term().Printf("Date:   %s\n", obj.Author.When.Format("Mon Jan 2 15:04:05 2006 -0700"))
	g.Term().Printf("Message: %s\n", obj.Message)
	g.Term().Printf("\n")
	return nil
}

// Checks for unpushed commits and pushes them if any are found
func (g *gitMeta) pushCommitsIfAny() error {

	// Check for un-pushed commits
	cmdFetch := exec.Command("git", "fetch", "--quiet")
	if err := cmdFetch.Run(); err != nil {
		return fmt.Errorf("failed to fetch updates: %w", err)
	}
	cmdStatus := exec.Command("git", "status", "-sb")
	var statusOut bytes.Buffer
	cmdStatus.Stdout = &statusOut
	if err := cmdStatus.Run(); err != nil {
		return fmt.Errorf("failed to get git status: %w", err)
	}

	// Parse status output
	status := statusOut.String()
	if strings.Contains(status, "[ahead") {
		g.Term().Info().Println("There are un-pushed commits: Pushing...")

		// Push the commits
		cmdPush := exec.Command("git", "push")
		cmdPush.Stdout = &statusOut
		cmdPush.Stderr = &statusOut
		if err := cmdPush.Run(); err != nil {
			return fmt.Errorf("failed to push commits: %w", err)
		}
		g.Term().Info().Println("Successfully pushed commits.")
		g.Term().Printf("\n")
	} else {
		g.Log().Debug("No un-pushed commits found.")
	}

	return nil
}

func (g *gitMeta) pushBranchIfNotRemote() error {
	// Verify the remote name
	cmdRemote := exec.Command("git", "remote")
	var remoteOut bytes.Buffer
	cmdRemote.Stdout = &remoteOut
	if err := cmdRemote.Run(); err != nil {
		return fmt.Errorf("failed to list remotes: %w", err)
	}

	// Ensure "origin" exists in the list of remotes
	remoteList := strings.Split(strings.TrimSpace(remoteOut.String()), "\n")
	hasOrigin := false
	for _, remote := range remoteList {
		if strings.TrimSpace(remote) == "origin" {
			hasOrigin = true
			break
		}
	}
	if !hasOrigin {
		return fmt.Errorf("git remote server 'origin' not found; please ensure a remote server named 'origin' exists")
	}

	// Fetch updates to ensure we have the latest remote information
	cmdFetch := exec.Command("git", "fetch", "--quiet", "origin")
	if err := cmdFetch.Run(); err != nil {
		return fmt.Errorf("failed to fetch updates: %w", err)
	}

	// Get the current git status with tracking information
	cmdStatus := exec.Command("git", "status", "-sb")
	var statusOut bytes.Buffer
	cmdStatus.Stdout = &statusOut
	if err := cmdStatus.Run(); err != nil {
		return fmt.Errorf("failed to get git status: %w", err)
	}

	// Parse the output of `git status -sb`
	status := strings.TrimSpace(statusOut.String())
	if !strings.HasPrefix(status, "##") {
		return fmt.Errorf("unexpected git status output: %s", status)
	}

	// Extract branch info
	statusLine := strings.TrimPrefix(status, "## ")
	parts := strings.Split(statusLine, "...")
	branchName := parts[0]

	if len(parts) == 1 {
		// No remote tracking information means the branch is local-only
		g.Term().Info().Printf("Branch '%s' exists locally but not remotely: Pushing...\n", branchName)

		// Push the branch to the remote
		cmdPush := exec.Command("git", "push", "--set-upstream", "origin", branchName)
		cmdPush.Stdout = &statusOut
		cmdPush.Stderr = &statusOut
		if err := cmdPush.Run(); err != nil {
			return fmt.Errorf("failed to push branch '%s': %w", branchName, err)
		}
		g.Term().Info().Println("Successfully pushed branch")
	} else {
		g.Log().Debug("Branch '%s' already exists remotely", "branch", branchName)
	}

	return nil
}
