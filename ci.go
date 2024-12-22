package plasmactlmeta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/launchrctl/launchr"
)

const targetJobName = "platform:deploy"

// OAuthResponse is a struct to parse OAuth response.
type OAuthResponse struct {
	AccessToken string `json:"access_token"`
}

// PipelineResponse is a struct to parse OAuth response.
type PipelineResponse struct {
	ID             int    `json:"id"`
	WebURL         string `json:"web_url"`
	ProjectID      int    `json:"project_id"`
	DetailedStatus struct {
		DetailsPath string `json:"details_path"`
	} `json:"detailed_status"`
}

// Job struct for listing jobs in the pipeline
type Job struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	Stage        string `json:"stage"`
	AllowFailure bool   `json:"allow_failure"`
}

func getOAuthToken(gitlabDomain, username, password string) (string, error) {
	// Prepare the OAuth request
	oauthURL := fmt.Sprintf("%s/oauth/token", gitlabDomain)
	launchr.Log().Debug("OAuth token request URL", "url", oauthURL)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("username", username)
	data.Set("password", password)

	// Create HTTP request for OAuth token
	req, err := http.NewRequest("POST", oauthURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	launchr.Log().Debug("OAuth token response", "body", string(body))

	// Parse JSON response to extract access token
	var oauthResp OAuthResponse
	err = json.Unmarshal(body, &oauthResp)
	if err != nil {
		return "", err
	}

	return oauthResp.AccessToken, nil
}

func getBranchName() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func getRepoName() (string, error) {
	cmd := exec.Command("git", "config", "--get", "remote.origin.url")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	repoURL := strings.TrimSpace(string(output))
	repoParts := strings.Split(repoURL, "/")
	return strings.TrimSuffix(repoParts[len(repoParts)-1], ".git"), nil
}

func getProjectID(gitlabDomain, username, password, accessToken, repoName string) (string, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects?search=%s&access_token=%s", gitlabDomain, url.QueryEscape(repoName), accessToken)
	launchr.Log().Debug("GitLab API URL to get project ID", "url", apiURL)

	// Create the request
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(username, password)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Parse the response JSON
	var projects []map[string]interface{}
	err = json.Unmarshal(body, &projects)
	if err != nil {
		return "", err
	}
	if len(projects) == 0 {
		return "", fmt.Errorf("project not found")
	}
	return fmt.Sprintf("%.0f", projects[0]["id"].(float64)), nil
}

func triggerPipeline(gitlabDomain, username, password, accessToken, projectID, branchName, buildEnv, buildResources string, ansibleDebug bool) (int, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/pipeline?access_token=%s", gitlabDomain, projectID, accessToken)
	launchr.Log().Debug("GitLab API URL for triggering pipeline", "url", apiURL)

	// Prepare the variables to pass during pipeline creation
	data := map[string]interface{}{
		"ref": branchName,
		"variables": []map[string]string{
			{
				"key":   "PLASMA_BUILD_ENV",
				"value": buildEnv,
			},
			{
				"key":   "PLASMA_BUILD_RESOURCES",
				"value": buildResources,
			},
		},
	}

	// Only add BUILD_DEBUG_MODE if provided
	if ansibleDebug {
		launchr.Log().Info("Appending BUILD_DEBUG_MODE to pipelines variables")
		data["variables"] = append(data["variables"].([]map[string]string), map[string]string{
			"key":   "BUILD_DEBUG_MODE",
			"value": strconv.FormatBool(ansibleDebug),
		})
	}
	// Only add VERBOSITY if provided
	logLvl := launchr.Log().Level()
	if logLvl != launchr.LogLevelDisabled {
		logLvl := int(logLvl) - 1
		verbosity := "-" + strings.Repeat("v", int(launchr.LogLevelError)-logLvl)
		launchr.Log().Info("Appending VERBOSITY to pipelines variables")
		data["variables"] = append(data["variables"].([]map[string]string), map[string]string{
			"key":   "VERBOSITY",
			"value": verbosity,
		})
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return 0, err
	}
	launchr.Log().Debug("JSON data for triggering pipeline", "json", string(jsonData))

	// Create the request
	launchr.Term().Info().Printfln("Creating CI pipeline...")
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, err
	}

	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")

	launchr.Log().Debug("Request for triggering pipeline", "request", req)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	bodyStr := string(body)
	launchr.Log().Debug("Response for triggering pipeline", "body", bodyStr)

	// Check if the response contains "Reference not found"
	if strings.Contains(strings.ToLower(bodyStr), "reference not found") {
		return 0, fmt.Errorf("git branch not found: %s", bodyStr)
	}

	// Parse the response JSON to extract pipeline info
	var pipelineResp PipelineResponse
	err = json.Unmarshal(body, &pipelineResp)
	if err != nil {
		return 0, err
	}

	// Print Pipeline URL only once
	launchr.Term().Printfln("Pipeline URL: %s", pipelineResp.WebURL)

	// Return the pipeline ID
	return pipelineResp.ID, nil
}

func getJobsInPipeline(gitlabDomain, username, password, accessToken, projectID string, pipelineID int) ([]Job, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/pipelines/%d/jobs?access_token=%s", gitlabDomain, projectID, pipelineID, accessToken)
	launchr.Log().Debug("GitLab API URL for retrieving jobs", "url", apiURL)

	// Create the request
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	launchr.Log().Debug("GitLab API response for job", "body", string(body))

	// Parse the jobs in the pipeline
	var jobs []Job
	err = json.Unmarshal(body, &jobs)
	if err != nil {
		return nil, err
	}

	return jobs, nil
}

// Function to retrieve and continuously print the job trace
func getJobTrace(gitlabDomain, username, password, accessToken, projectID string, jobID int) error {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/jobs/%d/trace?access_token=%s", gitlabDomain, projectID, jobID, accessToken)
	launchr.Log().Debug("GitLab API URL for retrieving job trace", "url", apiURL)

	const maxRetries = 20               // Retry up to 20 times to ensure job has started
	const retryDelay = 10 * time.Second // Wait 10 seconds between retries

	// Retry until job has started and trace is available
	for i := 0; i < maxRetries; i++ {
		traceContent, err := fetchTrace(apiURL, username, password)
		if err != nil {
			return err
		}

		if len(traceContent) > 0 {
			launchr.Term().Println("Job has started!")
			break
		}

		launchr.Term().Println("Waiting for job to start...")
		time.Sleep(retryDelay)
	}

	// Start tailing the job trace
	launchr.Term().Println("Now tailing job's trace:")
	var lastLength int // Keeps track of how much trace has already been printed

	for {
		traceContent, err := fetchTrace(apiURL, username, password)
		if err != nil {
			return err
		}

		if len(traceContent) > lastLength {
			// Print only new trace content
			newContent := traceContent[lastLength:]
			launchr.Term().Print(newContent)
			lastLength = len(traceContent)
		}

		// If the trace has not changed for a while, assume it's still running
		if len(traceContent) == lastLength {
			launchr.Term().Print(".") // Indicate waiting
		}

		// Determine job completion status
		statusCode, completed := jobCompleted(traceContent)
		if completed {
			if statusCode == 0 {
				launchr.Term().Println("\nEnd of trace.")
				return nil // Exit with code 0
			}
			// If the job failed, return an error with the corresponding exit code
			return fmt.Errorf("job failed with exit code %d", statusCode)
		}

		// Sleep briefly before polling the trace again
		time.Sleep(5 * time.Second)
	}
}

// Helper function to determine if job has completed based on trace content and return exit code if failed
func jobCompleted(traceContent string) (int, bool) {
	if strings.Contains(traceContent, "Job succeeded") {
		return 0, true
	}

	if strings.Contains(traceContent, "Job failed") {
		// Extract the exit code from the trace content
		lines := strings.Split(traceContent, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Job failed") {
				parts := strings.Fields(line)
				if len(parts) > 3 {
					if code, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
						return code, true
					}
				}
			}
		}
	}
	return 1, false // Default to failed with exit code 1 if not found
}

// Helper function to fetch job trace from GitLab API
func fetchTrace(apiURL, username, password string) (string, error) {
	// Create the request
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(username, password)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body (the trace)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func triggerManualJob(gitlabDomain, username, password, accessToken, projectID string, jobID int, pipelineID int) error {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/jobs/%d/play?access_token=%s", gitlabDomain, projectID, jobID, accessToken)
	launchr.Log().Debug("GitLab API URL for triggering manual job", "url", apiURL)

	// Retry parameters
	const maxRetries = 100
	const retryDelay = 30 * time.Second

	var jobURL string // To store the Job URL

	// Print the Job URL at the very end of the function
	defer func() {
		if jobURL != "" {
			launchr.Term().Printfln("\nJob URL: %s", jobURL)
		}
	}()

	// Retrieve all jobs to determine the stage of the target job
	allJobs, err := getJobsInPipeline(gitlabDomain, username, password, accessToken, projectID, pipelineID)
	if err != nil {
		return err
	}

	// Find the stage of the target job
	var targetJobStage string
	for _, job := range allJobs {
		if job.ID == jobID {
			targetJobStage = job.Stage
			break
		}
	}
	if targetJobStage == "" {
		return fmt.Errorf("stage of %s job not found", targetJobName)
	}

	for i := 0; i < maxRetries; i++ {
		// Check the status of jobs in previous stages
		jobs, err := getJobsInPipeline(gitlabDomain, username, password, accessToken, projectID, pipelineID)
		if err != nil {
			return err
		}

		inProgress := []string{}
		failed := []string{}

		for _, job := range jobs {
			if job.Status == "running" || job.Status == "pending" {
				if job.Stage != targetJobStage { // Exclude jobs in the same stage
					inProgress = append(inProgress, job.Name)
				}
			} else if job.Status == "failed" && !job.AllowFailure {
				if job.Stage != targetJobStage { // Exclude jobs in the same stage
					failed = append(failed, job.Name)
				}
			}
		}

		// If there are failed jobs, no need to retry further
		if len(failed) > 0 {
			return fmt.Errorf("cannot trigger %s job due to failed jobs: %v", targetJobName, failed)
		}

		// If there are still jobs in progress, list them and wait before retrying
		if len(inProgress) > 0 {
			launchr.Term().Printfln("Waiting for previous jobs to finish: %v...", inProgress)
			time.Sleep(retryDelay)
			continue
		}

		// No failed jobs, no jobs in progress, proceed with triggering the manual job
		// Create the request to trigger the job
		req, err := http.NewRequest("POST", apiURL, nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth(username, password)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		launchr.Log().Debug("GitLab API response for triggering manual job", "body", string(body), "http_code", resp.StatusCode)

		// Check if response indicates success
		if resp.StatusCode == http.StatusOK {
			// Unmarshal the response body to extract the Job URL
			var jsonResponse struct {
				WebURL string `json:"web_url"`
			}
			if err := json.Unmarshal(body, &jsonResponse); err != nil {
				return fmt.Errorf("failed to unmarshal job response: %v", err)
			}

			jobURL = jsonResponse.WebURL // Save the Job URL for later printing

			// Print the Job URL
			launchr.Term().Printfln("Job URL: %s", jobURL)

			// Retrieve and print the job trace
			err = getJobTrace(gitlabDomain, username, password, accessToken, projectID, jobID)
			if err != nil {
				return fmt.Errorf("failed to retrieve job trace: %v", err)
			}
			return nil // End the program after successfully retrieving job trace
		}

		// Handle unplayable job response
		if strings.Contains(string(body), "Unplayable Job") {
			launchr.Term().Printfln("%s job cannot be played yet. Retrying in %v...", targetJobName, retryDelay)
			time.Sleep(retryDelay)
		} else {
			return fmt.Errorf("failed to trigger job: %s", resp.Status)
		}
	}

	return fmt.Errorf("failed to trigger job after %d retries", maxRetries)
}
