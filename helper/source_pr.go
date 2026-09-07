package helper

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
)

// Ambient CI variables that already hold a pull/merge-request number.
var sourcePREnvKeys = []string{
	"CI_EXTERNAL_PULL_REQUEST_IID",         // GitLab mirroring a GitHub PR
	"CI_MERGE_REQUEST_IID",                 // GitLab MR
	"SYSTEM_PULLREQUEST_PULLREQUESTNUMBER", // Azure Pipelines
	"CIRCLE_PR_NUMBER",                     // CircleCI (fork PRs)
	"CHANGE_ID",                            // Jenkins GitHub / GitLab PR plugins
}

var (
	pullRefRE = regexp.MustCompile(`^refs/pull/(\d+)/(?:merge|head)$`)
	pullURLRE = regexp.MustCompile(`/pull/(\d+)(?:/|$)`)
)

// sourcePRFromCI reads the triggering PR/MR number from the CI environment.
// Local runs and non-PR pipelines leave it unset — the user never passes it.
func sourcePRFromCI() *int {
	if n := detectSourcePR(); n > 0 {
		return &n
	}
	return nil
}

func detectSourcePR() int {
	if n := sourcePRFromGitHubRef(os.Getenv("GITHUB_REF")); n > 0 {
		return n
	}
	if n := sourcePRFromGitHubEvent(os.Getenv("GITHUB_EVENT_PATH")); n > 0 {
		return n
	}
	for _, key := range sourcePREnvKeys {
		if n := parsePositiveInt(os.Getenv(key)); n > 0 {
			return n
		}
	}
	if n := parsePositiveInt(os.Getenv("TRAVIS_PULL_REQUEST")); n > 0 {
		return n
	}
	if n := sourcePRFromPullURL(os.Getenv("CIRCLE_PULL_REQUEST")); n > 0 {
		return n
	}
	return 0
}

func sourcePRFromGitHubRef(ref string) int {
	m := pullRefRE.FindStringSubmatch(ref)
	if m == nil {
		return 0
	}
	return parsePositiveInt(m[1])
}

// sourcePRFromGitHubEvent reads GITHUB_EVENT_PATH (the Actions event payload).
// Covers pull_request, issue_comment on a PR, and workflow_run.
func sourcePRFromGitHubEvent(path string) int {
	if path == "" {
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var ev struct {
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
		Issue struct {
			Number      int             `json:"number"`
			PullRequest json.RawMessage `json:"pull_request"`
		} `json:"issue"`
		WorkflowRun struct {
			PullRequests []struct {
				Number int `json:"number"`
			} `json:"pull_requests"`
		} `json:"workflow_run"`
	}
	if json.Unmarshal(data, &ev) != nil {
		return 0
	}
	if ev.PullRequest.Number > 0 {
		return ev.PullRequest.Number
	}
	if len(ev.Issue.PullRequest) > 0 && ev.Issue.Number > 0 {
		return ev.Issue.Number
	}
	if len(ev.WorkflowRun.PullRequests) > 0 && ev.WorkflowRun.PullRequests[0].Number > 0 {
		return ev.WorkflowRun.PullRequests[0].Number
	}
	return 0
}

func sourcePRFromPullURL(raw string) int {
	m := pullURLRE.FindStringSubmatch(raw)
	if m == nil {
		return 0
	}
	return parsePositiveInt(m[1])
}

func parsePositiveInt(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0
	}
	return n
}
