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

// fakeGitHub serves the endpoints PushBranch calls; fileExists toggles the
// contents GET between 200 (update) and 404 (new file).
func fakeGitHub(t *testing.T, fileExists bool) (*httptest.Server, *[]string) {
	t.Helper()
	seen := &[]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+r.URL.Path)
		require.Equal(t, "Bearer ghtok", r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/git/ref/heads/master"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "BASESHA"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			require.Equal(t, "refs/heads/appknox-autofix/analysis-42", b["ref"])
			require.Equal(t, "BASESHA", b["sha"])
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			if !fileExists {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "OLDBLOB"})
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			require.Equal(t, "appknox-autofix/analysis-42", b["branch"])
			require.NotEmpty(t, b["content"]) // base64 patched content
			if fileExists {
				require.Equal(t, "OLDBLOB", b["sha"])
			} else {
				_, hasSHA := b["sha"]
				require.False(t, hasSHA) // new file: no sha
			}
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv, seen
}

func change() Change {
	return Change{
		Branch: "appknox-autofix/analysis-42", Path: "app/src/Main.java",
		Content: "fixed\n", Message: "fix(autofix): weak PRNG",
	}
}

func TestPushBranch_ExistingFile(t *testing.T) {
	srv, seen := fakeGitHub(t, true)
	defer srv.Close()
	url, err := PushBranch(context.Background(),
		Config{Owner: "appknox", Repo: "mfva", BaseRef: "master", Token: "ghtok", APIBase: srv.URL}, change())
	require.NoError(t, err)
	require.Contains(t, url, "/appknox/mfva/compare/master...appknox-autofix/analysis-42")
	require.Contains(t, *seen, "POST /repos/appknox/mfva/git/refs")
}

func TestPushBranch_NewFile(t *testing.T) {
	srv, _ := fakeGitHub(t, false)
	defer srv.Close()
	_, err := PushBranch(context.Background(),
		Config{Owner: "appknox", Repo: "mfva", BaseRef: "master", Token: "ghtok", APIBase: srv.URL}, change())
	require.NoError(t, err) // 404 on contents -> new file, no sha, still commits
}

func TestPushBranch_RequiresConfig(t *testing.T) {
	_, err := PushBranch(context.Background(), Config{Owner: "o", Repo: "r"}, change()) // no token
	require.Error(t, err)
}

func TestPushBranch_ReusesExistingBranch(t *testing.T) {
	// 422 "already exists" on the ref create must be treated as reuse (idempotent
	// re-run): commit the new patch onto the existing branch using ITS file sha.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/git/ref/heads/master"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "S"}})
		case strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Reference already exists"})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "BRANCHBLOB"})
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			require.Equal(t, "BRANCHBLOB", b["sha"]) // the branch's file sha, not base
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	url, err := PushBranch(context.Background(),
		Config{Owner: "o", Repo: "r", BaseRef: "master", Token: "ghtok", APIBase: srv.URL}, change())
	require.NoError(t, err)
	require.Contains(t, url, "/compare/")
}

func TestPushBranch_ResolvesDefaultBranch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r":
			_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "main"})
		case strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "S"}})
		case strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(http.StatusCreated)
		case strings.Contains(r.URL.Path, "/contents/"):
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	url, err := PushBranch(context.Background(),
		Config{Owner: "o", Repo: "r", Token: "ghtok", APIBase: srv.URL}, change()) // no BaseRef
	require.NoError(t, err)
	require.Contains(t, url, "/compare/main...") // resolved default branch
}

func TestWebBase(t *testing.T) {
	require.Equal(t, "https://github.com", webBase(Config{}))
	require.Equal(t, "https://ghe.corp", webBase(Config{APIBase: "https://ghe.corp/api/v3"}))
}
