package helper

import (
	"os"
	"strings"
)

// Repository identity read from the pipeline instead of from flags.
//
// Ported from feat/autofix-cli. In a CI job every one of these values is
// already in the environment, and asking the caller to restate them in workflow
// YAML adds three more things that can disagree with the checkout the job is
// actually holding. A flag that IS set always wins, so nothing here overrides
// an explicit choice: it only fills silence.

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

// repoFromCI reads owner/name from GitHub, GitLab or CircleCI.
//
// Every candidate is validated through splitRepo before it is accepted: the
// value reaches a URL path, so an unvalidated one could inject path or query
// segments (CWE-20).
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

// repoPathFromCI returns the checkout the job already has.
//
// Must exist AND be a directory: a stale or misspelt value would otherwise send
// the fixer at a path with no source in it, and the run would report "located
// nothing" rather than "there is no checkout here".
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

// refFromCI is the PR base branch (the compare target).
//
// GITHUB_BASE_REF is set only on pull_request jobs and is exactly the base
// there. On push and workflow_dispatch it is empty, and the branch out of
// GITHUB_REF is the useful answer -- without that fallback those jobs got an
// empty base and always compared against the repo default branch. Still empty
// falls through to ghpr, which resolves the repository's default branch.
func refFromCI() string {
	if r := strings.TrimSpace(os.Getenv("GITHUB_BASE_REF")); r != "" {
		return r
	}
	return branchFromGitHubRef(os.Getenv("GITHUB_REF"))
}

// branchFromGitHubRef extracts the branch from refs/heads/<branch>.
//
// Anything else -- refs/pull/N/merge, refs/tags/v1 -- yields "", because a
// merge ref is not a branch anyone can open a pull request against.
func branchFromGitHubRef(ref string) string {
	const heads = "refs/heads/"
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, heads) {
		return strings.TrimPrefix(ref, heads)
	}
	return ""
}

// validRepoSpec reports whether spec is a usable owner/name.
func validRepoSpec(spec string) bool {
	_, _, err := splitRepo(spec)
	return err == nil
}
