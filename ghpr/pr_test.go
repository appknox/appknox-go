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

// gitDB records what the Git Database API was asked to do, so a test can
// assert the SHAPE of the push -- how many blobs, how many commits -- rather
// than only that it returned no error.
type gitDB struct {
	seen         []string
	blobs        int
	commits      int
	treeEntries  []treeEntry
	baseTree     string
	commitMsg    string
	refUpdated   string
	branchExists bool
}

// fakeGitDB serves the endpoints PushFiles calls.
func fakeGitDB(t *testing.T, db *gitDB) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		db.seen = append(db.seen, r.Method+" "+r.URL.Path)
		require.Equal(t, "Bearer ghtok", r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/ref/heads/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object": map[string]string{"sha": "PARENTSHA"}})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			if db.branchExists {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"message": "Reference already exists"})
				return
			}
			w.WriteHeader(http.StatusCreated)

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/commits/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tree": map[string]string{"sha": "BASETREE"}})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/blobs"):
			db.blobs++
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "BLOB"})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/trees"):
			var b struct {
				BaseTree string      `json:"base_tree"`
				Tree     []treeEntry `json:"tree"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			db.baseTree, db.treeEntries = b.BaseTree, b.Tree
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "TREE"})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/commits"):
			db.commits++
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			db.commitMsg, _ = b["message"].(string)
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "NEWCOMMIT"})

		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/git/refs/heads/"):
			db.refUpdated = strings.SplitN(r.URL.Path, "/git/refs/heads/", 2)[1]
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/repos/o/r"):
			_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "develop"})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func pushCfg(srv *httptest.Server, base string) Config {
	return Config{Owner: "o", Repo: "r", BaseRef: base, Token: "ghtok", APIBase: srv.URL}
}

// The point of the Git Database path: many files, ONE commit. The Contents API
// this replaced wrote one commit per file, so no intermediate commit was ever
// a state the fixer intended.
func TestPushFiles_writesEveryFileInOneCommit(t *testing.T) {
	db := &gitDB{}
	srv := fakeGitDB(t, db)
	defer srv.Close()

	res, err := PushFiles(context.Background(), pushCfg(srv, "master"),
		"appknox-autofix/analysis-42",
		[]FileChange{
			{Path: "app/A.java", Content: "a"},
			{Path: "app/B.java", Content: "b"},
			{Path: "app/C.java", Content: "c"},
		}, "fix(autofix): three files")

	require.NoError(t, err)
	require.Equal(t, 3, db.blobs, "one blob per file")
	require.Equal(t, 1, db.commits, "exactly one commit for the whole scan")
	require.Len(t, db.treeEntries, 3)
	require.Equal(t, "BASETREE", db.baseTree, "tree must be a delta, not a replacement")
	require.Equal(t, "fix(autofix): three files", db.commitMsg)
	require.Equal(t, "NEWCOMMIT", res.CommitSHA)
	require.Equal(t, "appknox-autofix/analysis-42", res.Branch)
	require.Equal(t, "master", res.Base)
	require.Contains(t, res.URL, "/compare/master...appknox-autofix/analysis-42")
}

// Tree entries must carry a normal file mode, or GitHub rejects the tree.
func TestPushFiles_treeEntriesAreBlobsWithAFileMode(t *testing.T) {
	db := &gitDB{}
	srv := fakeGitDB(t, db)
	defer srv.Close()

	_, err := PushFiles(context.Background(), pushCfg(srv, "master"), "b",
		[]FileChange{{Path: "app/A.java", Content: "a"}}, "m")

	require.NoError(t, err)
	require.Equal(t, "100644", db.treeEntries[0].Mode)
	require.Equal(t, "blob", db.treeEntries[0].Type)
	require.Equal(t, "app/A.java", db.treeEntries[0].Path)
}

// A re-run must reuse the branch and add a commit, not fail.
func TestPushFiles_reusesAnExistingBranch(t *testing.T) {
	db := &gitDB{branchExists: true}
	srv := fakeGitDB(t, db)
	defer srv.Close()

	res, err := PushFiles(context.Background(), pushCfg(srv, "master"), "b",
		[]FileChange{{Path: "a.java", Content: "a"}}, "m")

	require.NoError(t, err)
	require.Equal(t, "NEWCOMMIT", res.CommitSHA)
}

// The branch name keeps its slash: %2F would name a branch containing a
// literal slash character rather than a path segment.
func TestPushFiles_keepsSlashesInTheBranchRef(t *testing.T) {
	db := &gitDB{}
	srv := fakeGitDB(t, db)
	defer srv.Close()

	_, err := PushFiles(context.Background(), pushCfg(srv, "master"),
		"appknox-autofix/analysis-42",
		[]FileChange{{Path: "a.java", Content: "a"}}, "m")

	require.NoError(t, err)
	require.Equal(t, "appknox-autofix/analysis-42", db.refUpdated)
}

func TestPushFiles_resolvesTheDefaultBranch(t *testing.T) {
	db := &gitDB{}
	srv := fakeGitDB(t, db)
	defer srv.Close()

	res, err := PushFiles(context.Background(), pushCfg(srv, ""), "b",
		[]FileChange{{Path: "a.java", Content: "a"}}, "m")

	require.NoError(t, err)
	require.Equal(t, "develop", res.Base)
}

func TestPushFiles_requiresConfigAndFiles(t *testing.T) {
	_, err := PushFiles(context.Background(), Config{Owner: "o", Repo: "r", Token: "t"}, "b", nil, "m")
	require.Error(t, err, "no files")

	_, err = PushFiles(context.Background(), Config{Owner: "o"}, "b",
		[]FileChange{{Path: "a", Content: "a"}}, "m")
	require.Error(t, err, "missing token")
}

// An empty subject must not produce a commit with no message.
func TestPushFiles_fallsBackToADefaultCommitMessage(t *testing.T) {
	db := &gitDB{}
	srv := fakeGitDB(t, db)
	defer srv.Close()

	_, err := PushFiles(context.Background(), pushCfg(srv, "master"), "b",
		[]FileChange{{Path: "a.java", Content: "a"}}, "")

	require.NoError(t, err)
	require.NotEmpty(t, db.commitMsg)
}

func TestWebBase(t *testing.T) {
	require.Equal(t, "https://github.com", webBase(Config{}))
	require.Equal(t, "https://ghe.corp", webBase(Config{APIBase: "https://ghe.corp/api/v3"}))
}
