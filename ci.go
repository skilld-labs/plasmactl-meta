package plasmactlmeta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/launchrctl/launchr/pkg/log"
)

const targetJobName = "platform:deploy"

// OAuth token response
type OAuthResponse struct {
	AccessToken string `json:"access_token"`
}

// Pipeline response
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
	log.Debug("OAuth token request URL: %s\n", oauthURL)

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
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	log.Debug("OAuth token response: %s\n", body)

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
	log.Debug("GitLab API URL for project search: %s\n", apiURL)

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

	body, err := ioutil.ReadAll(resp.Body)
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

func triggerPipeline(gitlabDomain, username, password, accessToken, projectID, branchName, buildEnv, buildResources, comparisonRef string) (int, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/pipeline?access_token=%s", gitlabDomain, projectID, accessToken)
	log.Debug("GitLab API URL for triggering pipeline: %s\n", apiURL)

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

	// Only add OVERRIDDEN_COMPARISON_REF if provided
	if comparisonRef != "" {
		log.Info("Appending OVERRIDDEN_COMPARISON_REF to other pipelines variables")
		data["variables"] = append(data["variables"].([]map[string]string), map[string]string{
			"key":   "OVERRIDDEN_COMPARISON_REF",
			"value": comparisonRef,
		})
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return 0, err
	}
	log.Debug("JSON data for triggering pipeline: %s\n", jsonData)

	// Create the request
	fmt.Printf("Creating CI pipeline...\n")
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	log.Debug("GitLab API response for triggering pipeline: %s\n", body)

	// Parse the response JSON to extract pipeline info
	var pipelineResp PipelineResponse
	err = json.Unmarshal(body, &pipelineResp)
	if err != nil {
		return 0, err
	}

	// Print Pipeline URL only once
	fmt.Printf("Pipeline URL: %s\n", pipelineResp.WebURL)

	// Return the pipeline ID
	return pipelineResp.ID, nil
}

func getJobsInPipeline(gitlabDomain, username, password, accessToken, projectID string, pipelineID int) ([]Job, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/pipelines/%d/jobs?access_token=%s", gitlabDomain, projectID, pipelineID, accessToken)
	log.Debug("GitLab API URL for retrieving jobs: %s\n", apiURL)

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

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	log.Debug("GitLab API response for jobs: %s\n", body)

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
	log.Debug("GitLab API URL for retrieving job trace: %s\n", apiURL)

	const maxRetries = 20               // Retry up to 20 times to ensure job has started
	const retryDelay = 10 * time.Second // Wait 10 seconds between retries

	// Retry until job has started and trace is available
	for i := 0; i < maxRetries; i++ {
		traceContent, err := fetchTrace(apiURL, username, password)
		if err != nil {
			return err
		}

		if len(traceContent) > 0 {
			fmt.Println("Job has started!")
			break
		}

		fmt.Printf("Waiting for job to start...\n")
		time.Sleep(retryDelay)
	}

	// Start tailing the job trace
	fmt.Println("Now tailing job's trace:")
	var lastLength int // Keeps track of how much trace has already been printed

	for {
		traceContent, err := fetchTrace(apiURL, username, password)
		if err != nil {
			return err
		}

		if len(traceContent) > lastLength {
			// Print only new trace content
			newContent := traceContent[lastLength:]
			fmt.Print(newContent)
			lastLength = len(traceContent)
		}

		// If the trace has not changed for a while, assume it's still running
		if len(traceContent) == lastLength {
			fmt.Print(".") // Indicate waiting
		}

		// Determine job completion status
		statusCode, completed := jobCompleted(traceContent)
		if completed {
			if statusCode == 0 {
				fmt.Println("\nEnd of trace.")
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
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func triggerManualJob(gitlabDomain, username, password, accessToken, projectID string, jobID int, pipelineID int) error {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/jobs/%d/play?access_token=%s", gitlabDomain, projectID, jobID, accessToken)
	log.Debug("GitLab API URL for triggering manual job: %s\n", apiURL)

	// Retry parameters
	const maxRetries = 100
	const retryDelay = 30 * time.Second

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
			fmt.Printf("Waiting for previous jobs to finish: %v...\n", inProgress)
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

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		log.Debug("GitLab API response for triggering manual job: %s\n", body)
		log.Debug("HTTP Status Code: %d\n", resp.StatusCode)

		// Check if response indicates success
		if resp.StatusCode == http.StatusOK {
			// Unmarshal the response body to extract the Job URL
			var jsonResponse struct {
				WebURL string `json:"web_url"`
			}
			if err := json.Unmarshal(body, &jsonResponse); err != nil {
				return fmt.Errorf("failed to unmarshal job response: %v", err)
			}

			// Print the Job URL
			fmt.Printf("Job URL: %s\n", jsonResponse.WebURL)

			// Retrieve and print the job trace
			err = getJobTrace(gitlabDomain, username, password, accessToken, projectID, jobID)
			if err != nil {
				return fmt.Errorf("failed to retrieve job trace: %v", err)
			}
			return nil // End the program after successfully retrieving job trace
		}

		// Handle unplayable job response
		if strings.Contains(string(body), "Unplayable Job") {
			fmt.Printf("%s job cannot be played yet. Retrying in %v...\n", targetJobName, retryDelay)
			time.Sleep(retryDelay)
		} else {
			return fmt.Errorf("failed to trigger job: %s", resp.Status)
		}
	}

	return fmt.Errorf("failed to trigger job after %d retries", maxRetries)
}
