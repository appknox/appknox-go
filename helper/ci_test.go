package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func clearCIRepoEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_WORKSPACE", "")
	t.Setenv("GITHUB_BASE_REF", "")
	t.Setenv("CI_PROJECT_PATH", "")
	t.Setenv("CI_PROJECT_DIR", "")
	t.Setenv("CIRCLE_PROJECT_USERNAME", "")
	t.Setenv("CIRCLE_PROJECT_REPONAME", "")
}

func TestApplyCIDefaults_GitHubActions(t *testing.T) {
	clearCIRepoEnv(t)
	ws := t.TempDir()
	t.Setenv("GITHUB_REPOSITORY", "appknox/mfva")
	t.Setenv("GITHUB_WORKSPACE", ws)
	t.Setenv("GITHUB_BASE_REF", "master")

	got := applyCIDefaults(AutofixOptions{})
	require.Equal(t, "appknox/mfva", got.Repo)
	require.Equal(t, ws, got.RepoPath)
	require.Equal(t, "master", got.Ref)
}

func TestApplyCIDefaults_DoesNotOverrideSetFields(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_REPOSITORY", "ci/from-env")
	t.Setenv("GITHUB_BASE_REF", "develop")

	got := applyCIDefaults(AutofixOptions{Repo: "appknox/mfva", RepoPath: "/tmp/src", Ref: "main"})
	require.Equal(t, "appknox/mfva", got.Repo)
	require.Equal(t, "/tmp/src", got.RepoPath)
	require.Equal(t, "main", got.Ref)
}

func TestRepoFromCI_Circle(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("CIRCLE_PROJECT_USERNAME", "appknox")
	t.Setenv("CIRCLE_PROJECT_REPONAME", "mfva")
	require.Equal(t, "appknox/mfva", repoFromCI())
}

func TestRepoFromCI_RejectsInvalid(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_REPOSITORY", "not a repo")
	require.Empty(t, repoFromCI())
}

func TestRepoPathFromCI_IgnoresMissingDir(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_WORKSPACE", "/definitely/not/here")
	require.Empty(t, repoPathFromCI())
}
