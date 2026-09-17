package ghpr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultAPIBase       = "https://api.github.com"
	httpTimeout          = 60 * time.Second
	maxRespBytes         = 8 << 20 // cap any GitHub response (OOM guard)
	fileMode             = "100644"
	maxRefUpdateAttempts = 5
)

// Config identifies the repo + base ref and carries the GitHub token.
type Config struct {
	Owner   string
	Repo    string
	BaseRef string // base to branch from; empty = the repo's default branch
	Token   string
	APIBase string // empty = https://api.github.com (set for GHES)
}

func (c Config) apiBase() string {
	if c.APIBase != "" {
		return strings.TrimRight(c.APIBase, "/")
	}
	return defaultAPIBase
}

func (c Config) repoURL(path string) string {
	base := fmt.Sprintf("%s/repos/%s/%s", c.apiBase(), c.Owner, c.Repo)
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return base
	}
	return base + "/" + path
}

// Change is the branch + single patched file + commit message to push.
type Change struct {
	Branch  string
	Path    string
	Content string
	Message string
}

// FileChange is one patched file (path + content).
type FileChange struct {
	Path    string
	Content string
}

// Result is the outcome of pushing a branch (compare URL + commit SHA).
type Result struct {
	URL       string // compare URL that pre-fills a PR
	Branch    string
	Base      string
	CommitSHA string // SHA of the single commit that contains every patched file
}

// PushBranch pushes a single patched file to a new branch (thin wrapper).
func PushBranch(ctx context.Context, cfg Config, ch Change) (Result, error) {
	return PushFiles(ctx, cfg, ch.Branch, []FileChange{{Path: ch.Path, Content: ch.Content}}, ch.Message)
}

// PushFiles creates a branch off the base ref and writes every patched file in
// one git commit (Git Database API). Idempotent: an existing branch is reused.
// The Result URL is a compare link; OpenPullRequest replaces it with the opened PR.
func PushFiles(ctx context.Context, cfg Config, branch string, files []FileChange, message string) (Result, error) {
	if cfg.Owner == "" || cfg.Repo == "" || cfg.Token == "" {
		return Result{}, errors.New("ghpr: owner, repo, and token are required")
	}
	if len(files) == 0 {
		return Result{}, errors.New("ghpr: no files to push")
	}
	base, err := resolveBase(ctx, cfg)
	if err != nil {
		return Result{}, err
	}
	baseSHA, err := branchSHA(ctx, cfg, base)
	if err != nil {
		return Result{}, err
	}
	if err := createBranch(ctx, cfg, branch, baseSHA); err != nil {
		return Result{}, err
	}
	if message == "" {
		message = "fix(autofix): apply scan fixes"
	}
	sha, err := commitFiles(ctx, cfg, branch, files, message)
	if err != nil {
		return Result{}, err
	}
	return Result{
		URL:       compareURL(cfg, base, branch),
		Branch:    branch,
		Base:      base,
		CommitSHA: sha,
	}, nil
}

// resolveBase returns the configured base ref or the repo's default branch.
func resolveBase(ctx context.Context, cfg Config) (string, error) {
	if cfg.BaseRef != "" {
		return cfg.BaseRef, nil
	}
	return defaultBranch(ctx, cfg)
}

// commitFiles writes every file into one commit on branch and points the ref at it.
// Parallel jobs sharing the head can lose a non-fast-forward race; retry by
// re-reading the tip and rebuilding the commit.
func commitFiles(ctx context.Context, cfg Config, branch string, files []FileChange, message string) (string, error) {
	var last error
	for i := 0; i < maxRefUpdateAttempts; i++ {
		sha, err := commitFilesOnce(ctx, cfg, branch, files, message)
		if err == nil {
			return sha, nil
		}
		last = err
		if !isNotFastForward(err) {
			return "", err
		}
	}
	return "", last
}

func commitFilesOnce(ctx context.Context, cfg Config, branch string, files []FileChange, message string) (string, error) {
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

func isNotFastForward(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "422") {
		return false
	}
	return strings.Contains(msg, "fast-forward") || strings.Contains(msg, "fast forward")
}

func defaultBranch(ctx context.Context, cfg Config) (string, error) {
	var out struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := cfg.do(ctx, http.MethodGet, cfg.repoURL(""), nil, &out); err != nil {
		return "", err
	}
	if out.DefaultBranch == "" {
		return "", errors.New("ghpr: could not resolve default branch")
	}
	return out.DefaultBranch, nil
}

func branchSHA(ctx context.Context, cfg Config, ref string) (string, error) {
	var out struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := cfg.do(ctx, http.MethodGet, cfg.repoURL("git/ref/heads/"+refPath(ref)), nil, &out); err != nil {
		return "", err
	}
	if out.Object.SHA == "" {
		return "", fmt.Errorf("ghpr: no sha for base ref %q", ref)
	}
	return out.Object.SHA, nil
}

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

func updateRef(ctx context.Context, cfg Config, branch, sha string) error {
	body := map[string]any{"sha": sha, "force": false}
	return cfg.do(ctx, http.MethodPatch, cfg.repoURL("git/refs/heads/"+refPath(branch)), body, nil)
}

// createBranch creates the branch, treating an already-existing branch as success
// so re-runs are idempotent (the new commit is then parented on the branch tip).
func createBranch(ctx context.Context, cfg Config, branch, sha string) error {
	body := map[string]string{"ref": "refs/heads/" + branch, "sha": sha}
	err := cfg.do(ctx, http.MethodPost, cfg.repoURL("git/refs"), body, nil)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		return nil
	}
	return err
}

// refPath keeps slashes in branch names (appknox-autofix/feat/login).
func refPath(ref string) string {
	return strings.ReplaceAll(url.PathEscape(ref), "%2F", "/")
}

type pullRequest struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
	Body    string `json:"body"`
	Head    struct {
		Ref string `json:"ref"`
	} `json:"head"`
}

// OpenPullRequest opens a PR from branch into base and returns its html_url.
// An already-open PR for the same head+base is reused (body appended). After
// that PR is closed or merged, a new PR is opened when the head has new commits.
func OpenPullRequest(ctx context.Context, cfg Config, base, branch, title, body string) (string, error) {
	if cfg.Owner == "" || cfg.Repo == "" || cfg.Token == "" {
		return "", errors.New("ghpr: owner, repo, and token are required")
	}
	if base == "" || branch == "" {
		return "", errors.New("ghpr: base and branch are required")
	}
	if title == "" {
		title = "Appknox autofix"
	}
	if existing, ok, err := lookupPR(ctx, cfg, base, branch, "open"); err != nil {
		return "", err
	} else if ok {
		_ = appendPRBody(ctx, cfg, existing, body)
		return existing.HTMLURL, nil
	}
	var out struct {
		HTMLURL string `json:"html_url"`
	}
	err := cfg.do(ctx, http.MethodPost, cfg.repoURL("pulls"), map[string]string{
		"title": title,
		"head":  branch,
		"base":  base,
		"body":  body,
	}, &out)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already exists") {
			existing, ok, findErr := lookupPR(ctx, cfg, base, branch, "open")
			if findErr != nil {
				return "", findErr
			}
			if !ok {
				return "", fmt.Errorf("ghpr: pull request already exists but could not be found for %s: %w", branch, err)
			}
			_ = appendPRBody(ctx, cfg, existing, body)
			return existing.HTMLURL, nil
		}
		return "", err
	}
	if out.HTMLURL == "" {
		return "", errors.New("ghpr: pull request created but html_url was empty")
	}
	return out.HTMLURL, nil
}

func lookupPR(ctx context.Context, cfg Config, base, branch, state string) (pullRequest, bool, error) {
	pulls, err := listPulls(ctx, cfg, base, branch, state, true)
	if err != nil {
		return pullRequest{}, false, err
	}
	if len(pulls) > 0 && pulls[0].HTMLURL != "" {
		return pulls[0], true, nil
	}
	pulls, err = listPulls(ctx, cfg, base, "", state, false)
	if err != nil {
		return pullRequest{}, false, err
	}
	for _, p := range pulls {
		if p.Head.Ref == branch && p.HTMLURL != "" {
			return p, true, nil
		}
	}
	return pullRequest{}, false, nil
}

func listPulls(ctx context.Context, cfg Config, base, branch, state string, withHead bool) ([]pullRequest, error) {
	q := url.Values{
		"base":     {base},
		"state":    {state},
		"per_page": {"100"},
	}
	if withHead && branch != "" {
		q.Set("head", cfg.Owner+":"+branch)
	}
	var out []pullRequest
	err := cfg.do(ctx, http.MethodGet, cfg.repoURL("pulls")+"?"+q.Encode(), nil, &out)
	return out, err
}

func appendPRBody(ctx context.Context, cfg Config, pr pullRequest, extra string) error {
	extra = strings.TrimSpace(extra)
	if extra == "" || pr.Number == 0 {
		return nil
	}
	merged := extra
	if strings.TrimSpace(pr.Body) != "" {
		merged = strings.TrimRight(pr.Body, "\n") + "\n\n---\n\n" + extra
	}
	return cfg.do(ctx, http.MethodPatch, cfg.repoURL(fmt.Sprintf("pulls/%d", pr.Number)),
		map[string]string{"body": merged}, nil)
}

// compareURL is the "open a PR" page for base...branch.
func compareURL(cfg Config, base, branch string) string {
	return fmt.Sprintf("%s/%s/%s/compare/%s...%s?expand=1", webBase(cfg), cfg.Owner, cfg.Repo, base, branch)
}

// webBase maps the API base to the web base (github.com for the public API).
func webBase(cfg Config) string {
	if cfg.APIBase == "" || strings.Contains(cfg.apiBase(), "api.github.com") {
		return "https://github.com"
	}
	return strings.TrimSuffix(strings.TrimSuffix(cfg.apiBase(), "/api/v3"), "/api")
}

// do performs a GitHub REST call, requires a 2xx, and decodes JSON into out.
func (c Config) do(ctx context.Context, method, rawURL string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ghpr: %s %s -> HTTP %d: %s", method, req.URL.Path, resp.StatusCode, ghMessage(data))
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// ghMessage extracts GitHub's error "message" field for clearer errors.
func ghMessage(data []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &e) == nil {
		return e.Message
	}
	return ""
}
