package helper

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// KnoxFixerBranchPrefix is reserved for knoxfixer PR branches. Runs on such a
// branch are skipped (and pass) so knoxfixer never loops on its own PRs.
const KnoxFixerBranchPrefix = "appknox-knoxfixer/"

// knoxFixerCIEnv is the CI context. Only RepoURL, BaseBranch and Provider go
// to Mycroft; the rest stays in the CLI.
type knoxFixerCIEnv struct {
	Provider   string // "github_actions"
	ServerURL  string // https://github.com
	APIURL     string // https://api.github.com
	Repository string // owner/repo
	RepoURL    string // https://github.com/owner/repo
	BaseBranch string // CI branch: PR source branch or pushed branch
	BaseSHA    string // commit the CI run built
	EventName  string
}

type githubEvent struct {
	PullRequest *struct {
		Head struct {
			SHA  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
				Fork     bool   `json:"fork"`
			} `json:"repo"`
		} `json:"head"`
		Base struct {
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"base"`
	} `json:"pull_request"`
}

// errKnoxFixerBranchSkip means "this is a knoxfixer branch: skip and pass".
var errKnoxFixerBranchSkip = errors.New("knoxfixer does not work on appknox-knoxfixer branch")

func readKnoxFixerCIEnv(getenv func(string) string) (*knoxFixerCIEnv, error) {
	if getenv("GITHUB_ACTIONS") != "true" {
		return nil, errors.New("knoxfixer currently supports GitHub Actions only (GITHUB_ACTIONS is not set)")
	}
	env := &knoxFixerCIEnv{
		Provider:   "github_actions",
		ServerURL:  strings.TrimRight(firstNonEmpty(getenv("GITHUB_SERVER_URL"), "https://github.com"), "/"),
		APIURL:     strings.TrimRight(firstNonEmpty(getenv("GITHUB_API_URL"), "https://api.github.com"), "/"),
		Repository: getenv("GITHUB_REPOSITORY"),
		EventName:  getenv("GITHUB_EVENT_NAME"),
		BaseSHA:    getenv("GITHUB_SHA"),
	}
	if env.Repository == "" || !strings.Contains(env.Repository, "/") {
		return nil, errors.New("GITHUB_REPOSITORY is not set")
	}
	env.RepoURL = env.ServerURL + "/" + env.Repository

	switch env.EventName {
	case "pull_request_target":
		return nil, errors.New("knoxfixer refuses to run on pull_request_target events")
	case "pull_request":
		env.BaseBranch = getenv("GITHUB_HEAD_REF")
		event, err := readGitHubEvent(getenv("GITHUB_EVENT_PATH"))
		if err != nil {
			return nil, err
		}
		if event.PullRequest == nil {
			return nil, errors.New("pull_request event payload has no pull_request")
		}
		head := event.PullRequest.Head
		if head.Repo.Fork || !strings.EqualFold(head.Repo.FullName, event.PullRequest.Base.Repo.FullName) {
			return nil, errors.New("knoxfixer refuses to run on pull requests from forks")
		}
		// The workspace is the refs/pull/N/merge commit; work on the PR
		// source branch tip that was built instead.
		env.BaseSHA = head.SHA
	default:
		if getenv("GITHUB_REF_TYPE") == "tag" {
			return nil, errors.New("knoxfixer needs a branch build (tag builds are not supported)")
		}
		env.BaseBranch = getenv("GITHUB_REF_NAME")
	}
	if env.BaseBranch == "" {
		return nil, errors.New("could not determine the CI branch (detached HEAD?)")
	}
	if strings.HasPrefix(env.BaseBranch, KnoxFixerBranchPrefix) {
		return env, errKnoxFixerBranchSkip
	}
	if env.BaseSHA == "" {
		return nil, errors.New("GITHUB_SHA is not set")
	}
	return env, nil
}

func readGitHubEvent(path string) (*githubEvent, error) {
	if path == "" {
		return nil, errors.New("GITHUB_EVENT_PATH is not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read GitHub event payload: %w", err)
	}
	var event githubEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("could not parse GitHub event payload: %w", err)
	}
	return &event, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
