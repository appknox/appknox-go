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

const (
	testCommitSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testTreeSHA   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testBlobSHA   = "cccccccccccccccccccccccccccccccccccccccc"
)

// fakeGitHub serves the Git Database endpoints PushFiles calls.
func fakeGitHub(t *testing.T, branchSHA string, createRefStatus int) (*httptest.Server, *[]string) {
	t.Helper()
	if branchSHA == "" {
		branchSHA = "BASESHA"
	}
	if createRefStatus == 0 {
		createRefStatus = http.StatusCreated
	}
	seen := &[]string{}
	blobs := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+r.URL.Path)
		require.Equal(t, "Bearer ghtok", r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/git/ref/heads/master"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "BASESHA"}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/ref/heads/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": branchSHA}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			require.True(t, strings.HasPrefix(b["ref"], "refs/heads/"))
			require.Equal(t, "BASESHA", b["sha"])
			if createRefStatus >= 400 {
				w.WriteHeader(createRefStatus)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "Reference already exists"})
				return
			}
			w.WriteHeader(createRefStatus)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/commits/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"tree": map[string]string{"sha": testTreeSHA}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/blobs"):
			blobs++
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			require.Equal(t, "utf-8", b["encoding"])
			require.NotEmpty(t, b["content"])
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": testBlobSHA})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/trees"):
			var b struct {
				BaseTree string      `json:"base_tree"`
				Tree     []treeEntry `json:"tree"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			require.Equal(t, testTreeSHA, b.BaseTree)
			require.NotEmpty(t, b.Tree)
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "NEWTREE"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/commits"):
			var b struct {
				Message string   `json:"message"`
				Tree    string   `json:"tree"`
				Parents []string `json:"parents"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			require.NotEmpty(t, b.Message)
			require.Equal(t, "NEWTREE", b.Tree)
			require.Equal(t, []string{branchSHA}, b.Parents)
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": testCommitSHA})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/git/refs/heads/"):
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			require.Equal(t, testCommitSHA, b["sha"])
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

func change() Change {
	return Change{
		Branch: "appknox-autofix/analysis-42", Path: "app/src/Main.java",
		Content: "fixed\n", Message: "fix(autofix): weak PRNG",
	}
}

func TestPushBranch_CreatesOneCommit(t *testing.T) {
	srv, seen := fakeGitHub(t, "BASESHA", http.StatusCreated)
	res, err := PushBranch(context.Background(),
		Config{Owner: "appknox", Repo: "mfva", BaseRef: "master", Token: "ghtok", APIBase: srv.URL}, change())
	require.NoError(t, err)
	require.Contains(t, res.URL, "/appknox/mfva/compare/master...appknox-autofix/analysis-42")
	require.Equal(t, "appknox-autofix/analysis-42", res.Branch)
	require.Equal(t, "master", res.Base)
	require.Equal(t, testCommitSHA, res.CommitSHA)
	require.Contains(t, *seen, "POST /repos/appknox/mfva/git/refs")
	require.Contains(t, *seen, "POST /repos/appknox/mfva/git/blobs")
	require.Contains(t, *seen, "POST /repos/appknox/mfva/git/trees")
	require.Contains(t, *seen, "POST /repos/appknox/mfva/git/commits")
	require.Contains(t, *seen, "PATCH /repos/appknox/mfva/git/refs/heads/appknox-autofix/analysis-42")
}

func TestPushBranch_RequiresConfig(t *testing.T) {
	_, err := PushBranch(context.Background(), Config{Owner: "o", Repo: "r"}, change()) // no token
	require.Error(t, err)
}

func TestPushBranch_ReusesExistingBranch(t *testing.T) {
	srv, seen := fakeGitHub(t, "BRANCHSHA", http.StatusUnprocessableEntity)
	res, err := PushBranch(context.Background(),
		Config{Owner: "o", Repo: "r", BaseRef: "master", Token: "ghtok", APIBase: srv.URL}, change())
	require.NoError(t, err)
	require.Contains(t, res.URL, "/compare/")
	require.Equal(t, testCommitSHA, res.CommitSHA)
	require.Contains(t, *seen, "GET /repos/o/r/git/commits/BRANCHSHA") // parent is the existing tip
}

func TestPushBranch_ResolvesDefaultBranch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r":
			_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "main"})
		case strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "BASESHA"}})
		case strings.Contains(r.URL.Path, "/git/ref/heads/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "BASESHA"}})
		case strings.HasSuffix(r.URL.Path, "/git/refs") && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		case strings.Contains(r.URL.Path, "/git/commits/") && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"tree": map[string]string{"sha": testTreeSHA}})
		case strings.HasSuffix(r.URL.Path, "/git/blobs"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": testBlobSHA})
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "NEWTREE"})
		case strings.HasSuffix(r.URL.Path, "/git/commits") && r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": testCommitSHA})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/git/refs/heads/"):
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	res, err := PushBranch(context.Background(),
		Config{Owner: "o", Repo: "r", Token: "ghtok", APIBase: srv.URL}, change()) // no BaseRef
	require.NoError(t, err)
	require.Contains(t, res.URL, "/compare/main...") // resolved default branch
	require.Equal(t, "main", res.Base)
	require.Equal(t, testCommitSHA, res.CommitSHA)
}

func TestPushFiles_MultipleFilesOneCommit(t *testing.T) {
	blobs, commits := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/git/ref/heads/master"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "BASESHA"}})
		case strings.Contains(r.URL.Path, "/git/ref/heads/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "BASESHA"}})
		case strings.HasSuffix(r.URL.Path, "/git/refs") && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		case strings.Contains(r.URL.Path, "/git/commits/") && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"tree": map[string]string{"sha": testTreeSHA}})
		case strings.HasSuffix(r.URL.Path, "/git/blobs"):
			blobs++
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": testBlobSHA})
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			var b struct {
				Tree []treeEntry `json:"tree"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			require.Len(t, b.Tree, 2)
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "NEWTREE"})
		case strings.HasSuffix(r.URL.Path, "/git/commits") && r.Method == http.MethodPost:
			commits++
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": testCommitSHA})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/git/refs/heads/"):
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	res, err := PushFiles(context.Background(),
		Config{Owner: "o", Repo: "r", BaseRef: "master", Token: "ghtok", APIBase: srv.URL},
		"appknox-autofix/analysis-42",
		[]FileChange{
			{Path: "app/A.java", Content: "a"},
			{Path: "app/B.java", Content: "b"},
		},
		"fix(autofix): Appknox scan (file 42)")
	require.NoError(t, err)
	require.Equal(t, 2, blobs)   // one blob per file
	require.Equal(t, 1, commits) // one commit for all files
	require.Contains(t, res.URL, "/compare/master...appknox-autofix/analysis-42")
	require.Equal(t, testCommitSHA, res.CommitSHA)
}

func TestPushFiles_NoFiles(t *testing.T) {
	_, err := PushFiles(context.Background(), Config{Owner: "o", Repo: "r", Token: "t"}, "b", nil, "")
	require.Error(t, err)
}

func TestWebBase(t *testing.T) {
	require.Equal(t, "https://github.com", webBase(Config{}))
	require.Equal(t, "https://ghe.corp", webBase(Config{APIBase: "https://ghe.corp/api/v3"}))
}

func TestOpenPullRequest_CreatesPR(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/repos/appknox/mfva/pulls", r.URL.Path)
		var b map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&b))
		require.Equal(t, "master", b["base"])
		require.Equal(t, "appknox-autofix/analysis-42", b["head"])
		require.Contains(t, b["title"], "autofix")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"html_url": "https://github.com/appknox/mfva/pull/9"})
	}))
	defer srv.Close()
	url, err := OpenPullRequest(context.Background(),
		Config{Owner: "appknox", Repo: "mfva", Token: "ghtok", APIBase: srv.URL},
		"master", "appknox-autofix/analysis-42", "fix(autofix): weak PRNG", "body")
	require.NoError(t, err)
	require.Equal(t, "https://github.com/appknox/mfva/pull/9", url)
}

func TestOpenPullRequest_ReusesExisting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/pulls":
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "A pull request already exists for o:appknox-autofix/analysis-42"})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/pulls":
			require.Equal(t, "o:appknox-autofix/analysis-42", r.URL.Query().Get("head"))
			require.Equal(t, "master", r.URL.Query().Get("base"))
			_ = json.NewEncoder(w).Encode([]map[string]string{{"html_url": "https://github.com/o/r/pull/3"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	url, err := OpenPullRequest(context.Background(),
		Config{Owner: "o", Repo: "r", Token: "ghtok", APIBase: srv.URL},
		"master", "appknox-autofix/analysis-42", "t", "")
	require.NoError(t, err)
	require.Equal(t, "https://github.com/o/r/pull/3", url)
}
