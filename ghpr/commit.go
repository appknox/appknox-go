package ghpr

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// One commit for every patched file, via the Git Database API.
//
// Ported from feat/autofix-cli. The Contents API this replaces writes one
// commit PER FILE, so a scan that fixed six files produced six commits, each
// a tree that did not yet contain the other five. That is noisy to review and
// actively misleading to bisect: no intermediate commit represents a state the
// fixer ever intended.
//
// blob -> tree -> commit -> ref is four calls plus one per file, and lands the
// whole scan as a single reviewable change.

// fileMode is the git mode for a normal non-executable file.
const fileMode = "100644"

// Result is the outcome of pushing a branch.
type Result struct {
	URL       string // compare URL that pre-fills a PR
	Branch    string
	Base      string
	CommitSHA string // the single commit containing every patched file
}

// repoURL builds an API URL under the repository.
func (c Config) repoURL(path string) string {
	return fmt.Sprintf("%s/repos/%s/%s/%s", c.apiBase(), c.Owner, c.Repo, path)
}

// refPath keeps slashes in branch names (appknox-autofix/analysis-118).
//
// url.PathEscape turns "/" into "%2F", which GitHub reads as a branch whose
// name literally contains a slash character rather than as a path segment.
func refPath(ref string) string {
	return strings.ReplaceAll(url.PathEscape(ref), "%2F", "/")
}

// commitFiles writes every file into ONE commit on branch and moves the ref.
//
// Parented on the branch tip rather than the base, so a re-run adds a commit
// to the existing branch instead of orphaning what is already there.
func commitFiles(ctx context.Context, cfg Config, branch string, files []FileChange, message string) (string, error) {
	parent, err := branchSHA(ctx, cfg, branch)
	if err != nil {
		return "", err
	}
	baseTree, err := commitTreeSHA(ctx, cfg, parent)
	if err != nil {
		return "", err
	}
	entries := make([]treeEntry, 0, len(files))
	for _, f := range files {
		blob, err := createBlob(ctx, cfg, f.Content)
		if err != nil {
			return "", err
		}
		entries = append(entries, treeEntry{
			Path: f.Path, Mode: fileMode, Type: "blob", SHA: blob,
		})
	}
	tree, err := createTree(ctx, cfg, baseTree, entries)
	if err != nil {
		return "", err
	}
	sha, err := createCommit(ctx, cfg, message, tree, parent)
	if err != nil {
		return "", err
	}
	if err := updateRef(ctx, cfg, branch, sha); err != nil {
		return "", err
	}
	return sha, nil
}

// commitTreeSHA returns the tree a commit points at, used as base_tree so the
// new tree is a delta rather than a replacement of the whole repository.
func commitTreeSHA(ctx context.Context, cfg Config, commitSHA string) (string, error) {
	var out struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := cfg.do(ctx, http.MethodGet, cfg.repoURL("git/commits/"+commitSHA), nil, &out); err != nil {
		return "", err
	}
	if out.Tree.SHA == "" {
		return "", fmt.Errorf("ghpr: no tree for commit %s", commitSHA)
	}
	return out.Tree.SHA, nil
}

func createBlob(ctx context.Context, cfg Config, content string) (string, error) {
	var out struct {
		SHA string `json:"sha"`
	}
	body := map[string]string{"content": content, "encoding": "utf-8"}
	if err := cfg.do(ctx, http.MethodPost, cfg.repoURL("git/blobs"), body, &out); err != nil {
		return "", err
	}
	if out.SHA == "" {
		return "", errors.New("ghpr: blob created but sha was empty")
	}
	return out.SHA, nil
}

type treeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

func createTree(ctx context.Context, cfg Config, baseTree string, entries []treeEntry) (string, error) {
	var out struct {
		SHA string `json:"sha"`
	}
	body := map[string]any{"base_tree": baseTree, "tree": entries}
	if err := cfg.do(ctx, http.MethodPost, cfg.repoURL("git/trees"), body, &out); err != nil {
		return "", err
	}
	if out.SHA == "" {
		return "", errors.New("ghpr: tree created but sha was empty")
	}
	return out.SHA, nil
}

func createCommit(ctx context.Context, cfg Config, message, tree, parent string) (string, error) {
	var out struct {
		SHA string `json:"sha"`
	}
	body := map[string]any{
		"message": message,
		"tree":    tree,
		"parents": []string{parent},
	}
	if err := cfg.do(ctx, http.MethodPost, cfg.repoURL("git/commits"), body, &out); err != nil {
		return "", err
	}
	if out.SHA == "" {
		return "", errors.New("ghpr: commit created but sha was empty")
	}
	return out.SHA, nil
}

// updateRef moves the branch to sha. force is false: a fast-forward failure
// means something else moved the branch, which must surface rather than be
// silently overwritten.
func updateRef(ctx context.Context, cfg Config, branch, sha string) error {
	body := map[string]any{"sha": sha, "force": false}
	return cfg.do(ctx, http.MethodPatch, cfg.repoURL("git/refs/heads/"+refPath(branch)), body, nil)
}
