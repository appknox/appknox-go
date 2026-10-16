package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func clearSourcePREnv(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_REF", "")
	t.Setenv("GITHUB_EVENT_PATH", "")
	t.Setenv("TRAVIS_PULL_REQUEST", "")
	t.Setenv("CIRCLE_PULL_REQUEST", "")
	for _, key := range sourcePREnvKeys {
		t.Setenv(key, "")
	}
}

func TestSourcePRFromGitHubRef(t *testing.T) {
	require.Equal(t, 15, sourcePRFromGitHubRef("refs/pull/15/merge"))
	require.Equal(t, 7, sourcePRFromGitHubRef("refs/pull/7/head"))
	require.Equal(t, 0, sourcePRFromGitHubRef("refs/heads/main"))
	require.Equal(t, 0, sourcePRFromGitHubRef(""))
}

func TestSourcePRFromGitHubEvent_PullRequest(t *testing.T) {
	path := writeEvent(t, `{"pull_request":{"number":15}}`)
	require.Equal(t, 15, sourcePRFromGitHubEvent(path))
}

func TestSourcePRFromGitHubEvent_IssueCommentOnPR(t *testing.T) {
	path := writeEvent(t, `{"issue":{"number":22,"pull_request":{"url":"https://api.github.com/repos/o/r/pulls/22"}}}`)
	require.Equal(t, 22, sourcePRFromGitHubEvent(path))
}

func TestSourcePRFromGitHubEvent_IssueCommentNotPR(t *testing.T) {
	path := writeEvent(t, `{"issue":{"number":22}}`)
	require.Equal(t, 0, sourcePRFromGitHubEvent(path))
}

func TestSourcePRFromGitHubEvent_WorkflowRun(t *testing.T) {
	path := writeEvent(t, `{"workflow_run":{"pull_requests":[{"number":9}]}}`)
	require.Equal(t, 9, sourcePRFromGitHubEvent(path))
}

func TestSourcePRFromCI_GitHubActionsEvent(t *testing.T) {
	clearSourcePREnv(t)
	t.Setenv("GITHUB_REF", "refs/heads/feature")
	t.Setenv("GITHUB_EVENT_PATH", writeEvent(t, `{"pull_request":{"number":15}}`))
	got := sourcePRFromCI()
	require.NotNil(t, got)
	require.Equal(t, 15, *got)
}

func TestSourcePRFromCI_GitLab(t *testing.T) {
	clearSourcePREnv(t)
	t.Setenv("CI_MERGE_REQUEST_IID", "41")
	got := sourcePRFromCI()
	require.NotNil(t, got)
	require.Equal(t, 41, *got)
}

func TestSourcePRFromCI_CircleURL(t *testing.T) {
	clearSourcePREnv(t)
	t.Setenv("CIRCLE_PULL_REQUEST", "https://github.com/appknox/mfva/pull/15")
	got := sourcePRFromCI()
	require.NotNil(t, got)
	require.Equal(t, 15, *got)
}

func TestSourcePRFromCI_LocalRunUnset(t *testing.T) {
	clearSourcePREnv(t)
	require.Nil(t, sourcePRFromCI())
}

func TestParsePositiveInt(t *testing.T) {
	require.Equal(t, 0, parsePositiveInt("false"))
	require.Equal(t, 0, parsePositiveInt("0"))
	require.Equal(t, 0, parsePositiveInt(""))
	require.Equal(t, 12, parsePositiveInt("12"))
}

func writeEvent(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "event.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}
