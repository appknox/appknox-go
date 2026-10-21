package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writePREvent(t *testing.T, head, base string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "event.json")
	body := `{"pull_request":{"head":{"repo":{"full_name":"` + head + `"}},` +
		`"base":{"repo":{"full_name":"` + base + `"}}}}`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

func TestAutofixEventError(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	t.Setenv("GITHUB_REPOSITORY", "appknox/mfva")

	t.Setenv("GITHUB_EVENT_PATH", writePREvent(t, "appknox/mfva", "appknox/mfva"))
	require.NoError(t, AutofixEventError())

	t.Setenv("GITHUB_EVENT_PATH", writePREvent(t, "someone/mfva", "appknox/mfva"))
	require.ErrorIs(t, AutofixEventError(), errForkPR)

	// Refused even for a same-repository pull request: the event hands the
	// run its secrets whatever it checks out.
	t.Setenv("GITHUB_EVENT_NAME", "pull_request_target")
	t.Setenv("GITHUB_EVENT_PATH", writePREvent(t, "appknox/mfva", "appknox/mfva"))
	require.ErrorIs(t, AutofixEventError(), errPullRequestTarget)
}

func TestAutofixEventError_PushIsFine(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_EVENT_NAME", "push")
	require.NoError(t, AutofixEventError())
}
