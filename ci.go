package plasmactlmeta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/launchrctl/launchr"
	"github.com/launchrctl/launchr/pkg/action"
)

const targetJobName = "platform:deploy"

type continuousIntegration struct {
	action.WithLogger
	action.WithTerm
}

// Job struct for listing jobs in the pipeline
type Job struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	Stage        string `json:"stage"`
	AllowFailure bool   `json:"allow_failure"`
}

// 1. orySessionToken is used only to request GitLab OAuth token.
// 2. gitlabAccessToken is used in Authorization headers for all subsequent GitLab API calls.
func (c *continuousIntegration) getOAuthTokens(gitlabDomain, username, password string) (string, error) {
	// Get ui.action URL from Ory self‐service login flow JSON
	oryDomain := "https://auth.skilld.cloud"
	oryLoginApiPath := "/self-service/login/api"
	oryLoginApiURL := oryDomain + oryLoginApiPath
	c.Log().Debug("oryLoginApiURL", "url", oryLoginApiURL)

	req, err := http.NewRequest("GET", oryLoginApiURL, nil)
	if err != nil {
		return "", err
	}

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

	type oryLoginResponse struct {
		UI struct {
			Action string `json:"action"`
		} `json:"ui"`
	}
	var apiResp oryLoginResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("unable to unmarshal Ory login flow response: %w", err)
	}
	apiLoginFlowURL := apiResp.UI.Action
	c.Log().Debug("Ory login flow action URL", "url", apiLoginFlowURL)

	// POST JSON body to Ory login flow URL
	type oryLoginPayload struct {
		Method     string `json:"method"`
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}

	loginJSON := oryLoginPayload{
		Method:     "password",
		Identifier: username,
		Password:   password,
	}
	jsonBytes, err := json.Marshal(loginJSON)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Ory login payload: %w", err)
	}

	req, err = http.NewRequest("POST", apiLoginFlowURL, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client = &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	type orySessionResponse struct {
		SessionToken string `json:"session_token"`
	}
	var sr orySessionResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return "", fmt.Errorf("unable to unmarshal Ory session response: %w", err)
	}

	orySessionToken := sr.SessionToken
	if orySessionToken == "" {
		return "", fmt.Errorf("received empty session_token from Ory; response body: %s", string(body))
	}
	c.Log().Debug("orySessionToken", "value", orySessionToken)

	// Use orySessionToken as Bearer to get a GitLab OAuth token
	oauthURL := fmt.Sprintf("%s/oauth/token", gitlabDomain)
	c.Log().Debug("OAuth token request URL", "url", oauthURL)

	// Send JSON payload
	gitlabPayload := map[string]string{
		"grant_type": "password",
		"username":   username,
		"password":   password,
	}
	gitlabJSON, err := json.Marshal(gitlabPayload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal GitLab OAuth payload: %w", err)
	}

	req, err = http.NewRequest("POST", oauthURL, bytes.NewBuffer(gitlabJSON))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+orySessionToken)

	client = &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	c.Log().Debug("OAuth token response", "body", string(body))

	if resp.StatusCode != http.StatusOK {
		// If not 200, check if the response appears to be HTML.
		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(contentType, "application/json") {
			// Optionally, extract the <title> if it's an HTML page.
			re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
			matches := re.FindSubmatch(body)
			if len(matches) > 1 {
				title := string(matches[1])
				return "", fmt.Errorf("unexpected HTTP status: %s, HTML title: %s", resp.Status, title)
			}
		}
		return "", fmt.Errorf("unexpected HTTP status: %s, body: %s", resp.Status, body)
	}

	// OAuthResponse is a struct to parse GitLab OAuth response.
	type OAuthResponse struct {
		AccessToken string `json:"access_token"`
	}
	// Parse JSON response to extract access token.
	var oauthResp OAuthResponse
	if err := json.Unmarshal(body, &oauthResp); err != nil {
		return "", err
	}

	return oauthResp.AccessToken, nil
}

func (c *continuousIntegration) getBranchName() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (c *continuousIntegration) getRepoName() (string, error) {
	cmd := exec.Command("git", "config", "--get", "remote.origin.url")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	repoURL := strings.TrimSpace(string(output))
	repoParts := strings.Split(repoURL, "/")
	return strings.TrimSuffix(repoParts[len(repoParts)-1], ".git"), nil
}

// getProjectID calls GitLab API "/projects?search=<repoName>",
// sets Header "Authorization: Bearer <gitlabAccessToken>", and checks HTTP status first.
func (c *continuousIntegration) getProjectID(gitlabDomain, gitlabAccessToken, repoName string) (string, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects?search=%s", gitlabDomain, url.QueryEscape(repoName))
	c.Log().Debug("GitLab API URL to get project ID", "url", apiURL)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+gitlabAccessToken)

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

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitLab API %s returned status %s: %s",
			"getProjectID", resp.Status, string(body))
	}

	// Unmarshal into an array of project maps
	var projects []map[string]interface{}
	if err := json.Unmarshal(body, &projects); err != nil {
		return "", fmt.Errorf("cannot parse projects list: %w; raw response: %s", err, string(body))
	}
	if len(projects) == 0 {
		return "", fmt.Errorf("project not found (empty list returned)")
	}
	return fmt.Sprintf("%.0f", projects[0]["id"].(float64)), nil
}

// triggerPipeline calls GitLab API "/projects/<projectID>/pipeline",
// sets Header "Authorization: Bearer <gitlabAccessToken>"
func (c *continuousIntegration) triggerPipeline(gitlabDomain, gitlabAccessToken, projectID, branchName, buildEnv, buildResources string, ansibleDebug bool) (int, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/pipeline", gitlabDomain, projectID)
	c.Log().Debug("GitLab API URL for triggering pipeline", "url", apiURL)

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
		c.Log().Info("Appending BUILD_DEBUG_MODE to pipelines variables")
		data["variables"] = append(data["variables"].([]map[string]string), map[string]string{
			"key":   "BUILD_DEBUG_MODE",
			"value": strconv.FormatBool(ansibleDebug),
		})
	}
	// Only add VERBOSITY if provided
	logLvl := c.Log().Level()
	if logLvl != launchr.LogLevelDisabled {
		logLvl := int(logLvl) - 1
		verbosity := "-" + strings.Repeat("v", int(launchr.LogLevelError)-logLvl)
		c.Log().Info("Appending VERBOSITY to pipelines variables")
		data["variables"] = append(data["variables"].([]map[string]string), map[string]string{
			"key":   "VERBOSITY",
			"value": verbosity,
		})
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return 0, err
	}
	c.Log().Debug("JSON data for triggering pipeline", "json", string(jsonData))

	c.Term().Info().Printfln("Creating CI pipeline...")
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gitlabAccessToken)

	c.Log().Debug("Request for triggering pipeline", "request", req)

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
	c.Log().Debug("Response for triggering pipeline", "body", bodyStr)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GitLab API triggerPipeline returned status %s: %s", resp.Status, bodyStr)
	}
	// Check if the response contains "Reference not found"
	if strings.Contains(strings.ToLower(bodyStr), "reference not found") {
		return 0, fmt.Errorf("git branch not found: %s", bodyStr)
	}

	// PipelineResponse is a struct to parse pipeline response.
	type PipelineResponse struct {
		ID             int    `json:"id"`
		WebURL         string `json:"web_url"`
		ProjectID      int    `json:"project_id"`
		DetailedStatus struct {
			DetailsPath string `json:"details_path"`
		} `json:"detailed_status"`
	}
	var pipelineResp PipelineResponse
	if err := json.Unmarshal(body, &pipelineResp); err != nil {
		return 0, err
	}

	c.Term().Printfln("Pipeline URL: %s", pipelineResp.WebURL)
	return pipelineResp.ID, nil
}

// getJobsInPipeline calls GitLab API "/projects/<projectID>/pipelines/<pipelineID>/jobs",
// sets Header "Authorization: Bearer <gitlabAccessToken>"
func (c *continuousIntegration) getJobsInPipeline(gitlabDomain, gitlabAccessToken, projectID string, pipelineID int) ([]Job, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/pipelines/%d/jobs", gitlabDomain, projectID, pipelineID)
	c.Log().Debug("GitLab API URL for retrieving jobs", "url", apiURL)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+gitlabAccessToken)

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
	c.Log().Debug("GitLab API response for job", "body", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitLab API getJobsInPipeline returned status %s: %s", resp.Status, string(body))
	}

	var jobs []Job
	if err := json.Unmarshal(body, &jobs); err != nil {
		return nil, err
	}

	return jobs, nil
}

// getJobTrace calls GitLab API "/projects/<projectID>/jobs/<jobID>/trace",
// sets Header "Authorization: Bearer <gitlabAccessToken>" and tails the log until completion
func (c *continuousIntegration) getJobTrace(gitlabDomain, gitlabAccessToken, projectID string, jobID int) error {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/jobs/%d/trace", gitlabDomain, projectID, jobID)
	c.Log().Debug("GitLab API URL for retrieving job trace", "url", apiURL)

	const maxRetries = 20               // Retry up to 20 times to ensure job has started
	const retryDelay = 10 * time.Second // Wait 10 seconds between retries

	// Retry until job has started and trace is available
	for i := 0; i < maxRetries; i++ {
		traceContent, err := c.fetchTrace(apiURL, gitlabAccessToken)
		if err != nil {
			return err
		}

		if len(traceContent) > 0 {
			c.Term().Println("Job has started!")
			break
		}

		c.Term().Println("Waiting for job to start...")
		time.Sleep(retryDelay)
	}

	// Start tailing the job trace
	c.Term().Println("Now tailing job's trace:")
	var lastLength int // Keeps track of how much trace has already been printed

	for {
		traceContent, err := c.fetchTrace(apiURL, gitlabAccessToken)
		if err != nil {
			return err
		}

		if len(traceContent) > lastLength {
			// Print only new trace content
			newContent := traceContent[lastLength:]
			c.Term().Print(newContent)
			lastLength = len(traceContent)
		}

		// If the trace has not changed for a while, assume it's still running
		if len(traceContent) == lastLength {
			c.Term().Print(".") // Indicate waiting
		}

		// Determine job completion status
		statusCode, completed := c.jobCompleted(traceContent)
		if completed {
			if statusCode == 0 {
				c.Term().Println("\nEnd of trace.")
				return nil // Exit with code 0
			}
			// If the job failed, return an error with the corresponding exit code
			return fmt.Errorf("job failed with exit code %d", statusCode)
		}

		// Sleep briefly before polling the trace again
		time.Sleep(5 * time.Second)
	}
}

// jobCompleted determines if a GitLab job trace indicates completion.
// Returns (exitCode, true) if completed; otherwise (1, false).
func (c *continuousIntegration) jobCompleted(traceContent string) (int, bool) {
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
	return 1, false // Default: treat as failed with code=1 if no explicit indicator
}

// fetchTrace performs the GET request to the given trace URL, passing Header "Authorization: Bearer <gitlabAccessToken>"
func (c *continuousIntegration) fetchTrace(apiURL, gitlabAccessToken string) (string, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+gitlabAccessToken)

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

	return string(body), nil
}

// triggerManualJob calls GitLab API "/projects/<projectID>/jobs/<jobID>/play",
// sets Header "Authorization: Bearer <gitlabAccessToken>"
func (c *continuousIntegration) triggerManualJob(gitlabDomain, gitlabAccessToken, projectID string, jobID int, pipelineID int) error {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/jobs/%d/play", gitlabDomain, projectID, jobID)
	c.Log().Debug("GitLab API URL for triggering manual job", "url", apiURL)

	const maxRetries = 100
	const retryDelay = 30 * time.Second

	var jobURL string

	// Print the Job URL at the very end of the function
	defer func() {
		if jobURL != "" {
			c.Term().Printfln("Job URL: %s\n", jobURL)
		}
	}()

	// Retrieve all jobs to determine the stage of the target job
	allJobs, err := c.getJobsInPipeline(gitlabDomain, gitlabAccessToken, projectID, pipelineID)
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
		jobs, err := c.getJobsInPipeline(gitlabDomain, gitlabAccessToken, projectID, pipelineID)
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
			c.Term().Printfln("Waiting for previous jobs to finish: %v...", inProgress)
			time.Sleep(retryDelay)
			continue
		}

		// No failed jobs, no jobs in progress, proceed with triggering the manual job
		// Create the request to trigger the job
		req, err := http.NewRequest("POST", apiURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+gitlabAccessToken)

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
		c.Log().Debug("GitLab API response for triggering manual job", "body", string(body), "http_code", resp.StatusCode)

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
			c.Term().Printfln("Job URL: %s", jobURL)

			// Retrieve and print the job trace
			if err := c.getJobTrace(gitlabDomain, gitlabAccessToken, projectID, jobID); err != nil {
				return fmt.Errorf("failed to retrieve job trace: %v", err)
			}
			return nil // End the program after successfully retrieving job trace
		}

		// Handle unplayable job response
		if strings.Contains(string(body), "Unplayable Job") {
			c.Term().Printfln("%s job cannot be played yet. Retrying in %v...", targetJobName, retryDelay)
			time.Sleep(retryDelay)
		} else {
			return fmt.Errorf("failed to trigger job: %s", resp.Status)
		}
	}

	return fmt.Errorf("failed to trigger job after %d retries", maxRetries)
}
