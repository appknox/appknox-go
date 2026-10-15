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
	t.Setenv("GITHUB_HEAD_REF", "")
	t.Setenv("GITHUB_REF", "")
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("GITHUB_EVENT_PATH", "")
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
	t.Setenv("GITHUB_HEAD_REF", "feat/login")
	t.Setenv("GITHUB_REF", "refs/pull/15/merge")
	t.Setenv("GITHUB_REF_NAME", "15/merge")

	got := applyCIDefaults(AutofixOptions{})
	require.Equal(t, "appknox/mfva", got.Repo)
	require.Equal(t, ws, got.RepoPath)
	require.Equal(t, "master", got.Ref)
	require.Equal(t, "feat/login", got.HeadRef)
}

func TestApplyCIDefaults_GitHubPushBranch(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_REF", "refs/heads/feature/autofixbranch")
	t.Setenv("GITHUB_REF_NAME", "feature/autofixbranch")

	got := applyCIDefaults(AutofixOptions{})
	require.Equal(t, "feature/autofixbranch", got.HeadRef)
	require.Equal(t, "feature/autofixbranch", got.Ref) // push: PR into the branch that was pushed, not master
}

func TestApplyCIDefaults_HeadRefFillsMissingBase(t *testing.T) {
	clearCIRepoEnv(t)
	got := applyCIDefaults(AutofixOptions{HeadRef: "feat/login"})
	require.Equal(t, "feat/login", got.HeadRef)
	require.Equal(t, "feat/login", got.Ref)
}

func TestApplyCIDefaults_PrefersPullRequestBase(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_BASE_REF", "master")
	t.Setenv("GITHUB_HEAD_REF", "feat/login")
	t.Setenv("GITHUB_REF", "refs/pull/15/merge")

	got := applyCIDefaults(AutofixOptions{})
	require.Equal(t, "master", got.Ref)
	require.Equal(t, "feat/login", got.HeadRef)
}

func TestHeadRefFromCI_PullRequestUsesHeadRefIgnoresMergeRef(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_HEAD_REF", "feat/login")
	t.Setenv("GITHUB_REF", "refs/pull/15/merge")
	t.Setenv("GITHUB_REF_NAME", "15/merge")
	require.Equal(t, "feat/login", headRefFromCI())
}

func TestHeadRefFromCI_PushUsesHeadsRef(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_REF", "refs/heads/feat/x")
	t.Setenv("GITHUB_REF_NAME", "merge")
	require.Equal(t, "feat/x", headRefFromCI())
}

func TestHeadRefFromCI_TagPushEmpty(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_REF", "refs/tags/v1.0.0")
	require.Empty(t, headRefFromCI())
}

func TestRefFromCI_IgnoresPullMergeRef(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_REF", "refs/pull/15/merge")
	require.Empty(t, refFromCI())
}

func TestRefFromCI_PushUsesHeadsRef(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_REF", "refs/heads/feat/login")
	require.Equal(t, "feat/login", refFromCI())
}

func TestApplyCIDefaults_DoesNotOverrideSetFields(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_REPOSITORY", "ci/from-env")
	t.Setenv("GITHUB_BASE_REF", "develop")
	t.Setenv("GITHUB_HEAD_REF", "ci/from-env")

	got := applyCIDefaults(AutofixOptions{Repo: "appknox/mfva", RepoPath: "/tmp/src", Ref: "main", HeadRef: "feat/mine"})
	require.Equal(t, "appknox/mfva", got.Repo)
	require.Equal(t, "/tmp/src", got.RepoPath)
	require.Equal(t, "main", got.Ref)
	require.Equal(t, "feat/mine", got.HeadRef)
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

func TestForkPRFromCI_DifferentHeadRepo(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_EVENT_PATH", writeEvent(t, `{
		"pull_request": {
			"head": {"repo": {"full_name": "fork/mfva"}},
			"base": {"repo": {"full_name": "appknox/mfva"}}
		}
	}`))
	require.True(t, forkPRFromCI())
}

func TestForkPRFromCI_SameRepo(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_EVENT_PATH", writeEvent(t, `{
		"pull_request": {
			"head": {"repo": {"full_name": "appknox/mfva"}},
			"base": {"repo": {"full_name": "appknox/mfva"}}
		}
	}`))
	require.False(t, forkPRFromCI())
}

func TestForkPRFromCI_NoEvent(t *testing.T) {
	clearCIRepoEnv(t)
	require.False(t, forkPRFromCI())
}
