package helper

import (
	"encoding/json"
	"os"
	"strings"
)

// applyCIDefaults fills repo identity from the pipeline. Flags already set win.
func applyCIDefaults(opts AutofixOptions) AutofixOptions {
	if opts.Repo == "" {
		opts.Repo = repoFromCI()
	}
	if opts.RepoPath == "" {
		opts.RepoPath = repoPathFromCI()
	}
	if opts.Ref == "" {
		opts.Ref = refFromCI()
	}
	if opts.HeadRef == "" {
		opts.HeadRef = headRefFromCI()
	}
	return opts
}

func repoFromCI() string {
	if r := os.Getenv("GITHUB_REPOSITORY"); validRepoSpec(r) {
		return r
	}
	if r := os.Getenv("CI_PROJECT_PATH"); validRepoSpec(r) {
		return r
	}
	owner, name := os.Getenv("CIRCLE_PROJECT_USERNAME"), os.Getenv("CIRCLE_PROJECT_REPONAME")
	if spec := owner + "/" + name; owner != "" && name != "" && validRepoSpec(spec) {
		return spec
	}
	return ""
}

func repoPathFromCI() string {
	for _, key := range []string{"GITHUB_WORKSPACE", "CI_PROJECT_DIR"} {
		if p := strings.TrimSpace(os.Getenv(key)); p != "" {
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				return p
			}
		}
	}
	return ""
}

// refFromCI is the PR base branch (compare / merge target).
// Prefer GITHUB_BASE_REF on pull_request jobs. On push / workflow_dispatch it
// is empty so ghpr uses the repo default branch. Never GITHUB_REF_NAME
// (on pull_request that is often "merge" / "123/merge").
func refFromCI() string {
	return strings.TrimSpace(os.Getenv("GITHUB_BASE_REF"))
}

// headRefFromCI is the customer feature branch that keys the shared autofix PR.
// Prefer GITHUB_HEAD_REF on pull_request jobs; on push use the branch from
// GITHUB_REF (refs/heads/...). Never GITHUB_REF_NAME.
func headRefFromCI() string {
	if r := strings.TrimSpace(os.Getenv("GITHUB_HEAD_REF")); r != "" {
		return r
	}
	return branchFromGitHubRef(os.Getenv("GITHUB_REF"))
}

func branchFromGitHubRef(ref string) string {
	const heads = "refs/heads/"
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, heads) {
		return strings.TrimPrefix(ref, heads)
	}
	return ""
}

func validRepoSpec(spec string) bool {
	_, _, err := splitRepo(spec)
	return err == nil
}

// forkPRFromCI reports a pull_request whose head repo is not the base repo.
// Autofix cannot push that head with the base-repo token.
func forkPRFromCI() bool {
	head, base := forkReposFromGitHubEvent(os.Getenv("GITHUB_EVENT_PATH"))
	if head == "" {
		return false
	}
	if base == "" {
		base = os.Getenv("GITHUB_REPOSITORY")
	}
	return base != "" && !strings.EqualFold(head, base)
}

func forkReposFromGitHubEvent(path string) (headFullName, baseFullName string) {
	if path == "" {
		return "", ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	var ev struct {
		PullRequest struct {
			Head struct {
				Repo struct {
					FullName string `json:"full_name"`
				} `json:"repo"`
			} `json:"head"`
			Base struct {
				Repo struct {
					FullName string `json:"full_name"`
				} `json:"repo"`
			} `json:"base"`
		} `json:"pull_request"`
	}
	if json.Unmarshal(data, &ev) != nil {
		return "", ""
	}
	return ev.PullRequest.Head.Repo.FullName, ev.PullRequest.Base.Repo.FullName
}
