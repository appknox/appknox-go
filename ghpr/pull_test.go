package ghpr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func cfgFor(srv *httptest.Server) Config {
	return Config{Owner: "appknox", Repo: "mfva", Token: "ghtok", APIBase: srv.URL}
}

// ListPRFiles backs --scope pr: only files the developer actually touched in
// this PR may be patched.
func TestListPRFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/repos/appknox/mfva/pulls/13/files", r.URL.Path)
		require.Equal(t, "Bearer ghtok", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"filename": "app/src/main/java/com/appknox/mfva/MainActivity.java"},
			{"filename": "README.md"},
		})
	}))
	defer srv.Close()

	files, err := ListPRFiles(context.Background(), cfgFor(srv), 13)
	require.NoError(t, err)
	require.Equal(t, []string{
		"app/src/main/java/com/appknox/mfva/MainActivity.java", "README.md",
	}, files)
}

func TestListPRFiles_paginates(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("page") == "2" {
			_ = json.NewEncoder(w).Encode([]map[string]any{{"filename": "b.java"}})
			return
		}
		// A full page implies there may be more.
		page := make([]map[string]any, 100)
		for i := range page {
			page[i] = map[string]any{"filename": "a.java"}
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer srv.Close()

	files, err := ListPRFiles(context.Background(), cfgFor(srv), 13)
	require.NoError(t, err)
	require.Equal(t, 101, len(files), "second page must be fetched")
	require.Equal(t, 2, calls)
}

// The agreed flow ends at a DRAFT PR: CI runs and a human reviews before
// anything is mergeable.
func TestOpenDraftPR(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/repos/appknox/mfva/pulls", r.URL.Path)
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"number": 42, "html_url": "https://github.com/appknox/mfva/pull/42",
		})
	}))
	defer srv.Close()

	url, err := OpenDraftPR(context.Background(), cfgFor(srv), PullRequest{
		Branch: "bugfix/appknox-autofix-13-11829", Base: "master",
		Title: "Appknox Autofix: Weak PRNG", Body: "fixes it",
	})
	require.NoError(t, err)
	require.Equal(t, "https://github.com/appknox/mfva/pull/42", url)
	require.Equal(t, true, body["draft"], "the PR must be opened as a draft")
	require.Equal(t, "bugfix/appknox-autofix-13-11829", body["head"])
	require.Equal(t, "master", body["base"])
}

// Re-running autofix on the same finding must not open a second PR.
func TestFindOpenPR_returnsExisting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/repos/appknox/mfva/pulls", r.URL.Path)
		require.Equal(t, "appknox:fixbranch", r.URL.Query().Get("head"))
		require.Equal(t, "open", r.URL.Query().Get("state"))
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"number": 7, "html_url": "https://github.com/appknox/mfva/pull/7"},
		})
	}))
	defer srv.Close()

	url, err := FindOpenPR(context.Background(), cfgFor(srv), "fixbranch")
	require.NoError(t, err)
	require.Equal(t, "https://github.com/appknox/mfva/pull/7", url)
}

func TestFindOpenPR_emptyWhenNone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	}))
	defer srv.Close()

	url, err := FindOpenPR(context.Background(), cfgFor(srv), "fixbranch")
	require.NoError(t, err)
	require.Empty(t, url)
}

func TestOpenDraftPR_surfacesGitHubError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "No commits between master and fixbranch"})
	}))
	defer srv.Close()

	_, err := OpenDraftPR(context.Background(), cfgFor(srv), PullRequest{Branch: "fixbranch", Base: "master"})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "No commits"), "GitHub's reason must survive: %v", err)
}
