package helper

import (
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

// refFromCI is the PR base branch (compare target).
// Prefer GITHUB_BASE_REF on pull_request jobs; on push/workflow_dispatch use
// the branch from GITHUB_REF (refs/heads/...). Empty falls through to the
// repo default branch in ghpr.
func refFromCI() string {
	if r := strings.TrimSpace(os.Getenv("GITHUB_BASE_REF")); r != "" {
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
