package helper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/appknox/appknox-go/appknox"
	"github.com/stretchr/testify/require"
)

func TestPrTitle(t *testing.T) {
	require.Equal(t, "fix(autofix): Appknox scan (file 118)",
		prTitle(AutofixOptions{FileID: 118}))
	require.Equal(t, "fix(autofix): security findings",
		prTitle(AutofixOptions{}))
}

func TestPrBranch(t *testing.T) {
	require.Equal(t, "appknox-autofix/analysis-118", prBranch(118, "a.java"))
	require.Contains(t, prBranch(0, "app/Main.java"), "appknox-autofix/fix-") // no id → hashed
}

func TestCommitMessage(t *testing.T) {
	msg := commitMessage(filePatch{Finding: "Weak PRNG", Path: "app/src/Main.java"})
	require.Contains(t, msg, "Weak PRNG")
	require.Contains(t, msg, "Main.java") // basename, not the full path
}

func TestDeliverBranch_RequiresRepoAndToken(t *testing.T) {
	clearCIRepoEnv(t)
	patches := []filePatch{{Path: "app/A.java", Content: "c"}}
	_, err := deliverBranch(context.Background(), AutofixOptions{}, patches)
	require.Error(t, err) // no CI repo

	t.Setenv("GITHUB_TOKEN", "")
	_, err = deliverBranch(context.Background(), AutofixOptions{Repo: "o/r"}, patches)
	require.Error(t, err) // repo but no token
}

func TestDeliverBranch_UsesGitHubRepository(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_REPOSITORY", "appknox/mfva")
	t.Setenv("GITHUB_TOKEN", "")
	_, err := deliverBranch(context.Background(), AutofixOptions{},
		[]filePatch{{Path: "app/A.java", Content: "c"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "GitHub token") // repo came from CI; token is the remaining gap
}

func TestBuildAutofixPR(t *testing.T) {
	pr := buildAutofixPR(
		AutofixOptions{FileID: 118, Repo: "appknox/mfva", Ref: "master"},
		Delivery{
			URL:    "https://github.com/appknox/mfva/pull/42",
			Branch: "appknox-autofix/analysis-118", Base: "master",
			CommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		[]filePatch{{Path: "app/src/Main.java"}},
	)
	require.Equal(t, "appknox/mfva", pr.Repo)
	require.Equal(t, "master", pr.BaseBranch)
	require.Equal(t, "appknox-autofix/analysis-118", pr.Branch)
	require.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", pr.CommitSHA)
	require.Equal(t, "https://github.com/appknox/mfva/pull/42", pr.PRURL)
	require.Equal(t, []string{"app/src/Main.java"}, pr.PatchedFiles)
}

func TestReportAutofixPR_SkipsWithoutFileID(t *testing.T) {
	err := reportAutofixPRWith(context.Background(), nil,
		AutofixOptions{Finding: "weak PRNG"}, Delivery{}, nil)
	require.NoError(t, err) // manual --finding has nothing to attach to
}

func TestReportAutofixPR_PostsPayload(t *testing.T) {
	var got appknox.AutofixPR
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v2/files/118/autofix_prs", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "file": 118})
	})
	err := reportAutofixPRWith(context.Background(), client,
		AutofixOptions{FileID: 118, Repo: "appknox/mfva"},
		Delivery{
			URL:    "https://github.com/appknox/mfva/pull/42",
			Branch: "appknox-autofix/analysis-118", Base: "master",
			CommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		[]filePatch{{Path: "app/src/Main.java"}},
	)
	require.NoError(t, err)
	require.Equal(t, "appknox/mfva", got.Repo)
	require.Equal(t, "master", got.BaseBranch)
	require.Equal(t, "appknox-autofix/analysis-118", got.Branch)
	require.Equal(t, []string{"app/src/Main.java"}, got.PatchedFiles)
	require.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", got.CommitSHA)
	require.Zero(t, got.File) // request body does not send file; it is the URL
}

func testAppknoxClient(t *testing.T, h http.HandlerFunc) *appknox.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := appknox.NewClient("token")
	require.NoError(t, err)
	u, err := url.Parse(srv.URL + "/")
	require.NoError(t, err)
	c.BaseURL = u
	return c
}
