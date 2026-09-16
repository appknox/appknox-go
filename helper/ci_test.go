package helper

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// clearCI blanks every pipeline variable so one test cannot inherit another's
// environment, and so a developer running the suite inside CI gets the same
// result as one running it on a laptop.
func clearCI(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"GITHUB_REPOSITORY", "GITHUB_WORKSPACE", "GITHUB_BASE_REF", "GITHUB_REF",
		"CI_PROJECT_PATH", "CI_PROJECT_DIR",
		"CIRCLE_PROJECT_USERNAME", "CIRCLE_PROJECT_REPONAME",
	} {
		t.Setenv(k, "")
	}
}

func TestApplyCIDefaults_FillsFromGitHubActions(t *testing.T) {
	clearCI(t)
	dir := t.TempDir()
	t.Setenv("GITHUB_REPOSITORY", "appknox/mfva")
	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("GITHUB_REF", "refs/heads/develop")

	got := applyCIDefaults(AutofixOptions{})

	require.Equal(t, "appknox/mfva", got.Repo)
	require.Equal(t, dir, got.RepoPath)
	require.Equal(t, "develop", got.Ref)
}

// An explicit flag is a decision; the environment is only a default.
func TestApplyCIDefaults_NeverOverridesAFlag(t *testing.T) {
	clearCI(t)
	t.Setenv("GITHUB_REPOSITORY", "appknox/mfva")
	t.Setenv("GITHUB_WORKSPACE", t.TempDir())
	t.Setenv("GITHUB_REF", "refs/heads/develop")

	got := applyCIDefaults(AutofixOptions{
		Repo: "owner/other", RepoPath: "/somewhere", Ref: "main"})

	require.Equal(t, "owner/other", got.Repo)
	require.Equal(t, "/somewhere", got.RepoPath)
	require.Equal(t, "main", got.Ref)
}

// On a pull_request job the base is GITHUB_BASE_REF, not the merge ref.
func TestRefFromCI_PrefersThePullRequestBase(t *testing.T) {
	clearCI(t)
	t.Setenv("GITHUB_BASE_REF", "main")
	t.Setenv("GITHUB_REF", "refs/pull/42/merge")

	require.Equal(t, "main", refFromCI())
}

// A merge ref is not a branch anyone can target, so it must not become one.
func TestRefFromCI_IgnoresAMergeRef(t *testing.T) {
	clearCI(t)
	t.Setenv("GITHUB_REF", "refs/pull/42/merge")

	require.Empty(t, refFromCI())
}

// Push and workflow_dispatch jobs have no BASE_REF; the branch is the answer.
func TestRefFromCI_UsesTheBranchOnAPushJob(t *testing.T) {
	clearCI(t)
	t.Setenv("GITHUB_REF", "refs/heads/feature/x")

	require.Equal(t, "feature/x", refFromCI())
}

func TestRepoFromCI_ReadsGitLabAndCircle(t *testing.T) {
	clearCI(t)
	t.Setenv("CI_PROJECT_PATH", "group/app")
	require.Equal(t, "group/app", repoFromCI())

	clearCI(t)
	t.Setenv("CIRCLE_PROJECT_USERNAME", "appknox")
	t.Setenv("CIRCLE_PROJECT_REPONAME", "mfva")
	require.Equal(t, "appknox/mfva", repoFromCI())
}

// The value reaches a URL path, so a malformed spec must be refused rather
// than passed through (CWE-20).
func TestRepoFromCI_RejectsAMalformedSpec(t *testing.T) {
	clearCI(t)
	t.Setenv("GITHUB_REPOSITORY", "owner/repo?evil=1")

	require.Empty(t, repoFromCI())
}

// A path that is not a directory is worse than no path: the fixer would report
// "located nothing" instead of "there is no checkout here".
func TestRepoPathFromCI_RequiresAnExistingDirectory(t *testing.T) {
	clearCI(t)
	t.Setenv("GITHUB_WORKSPACE", filepath.Join(t.TempDir(), "absent"))

	require.Empty(t, repoPathFromCI())
}
