// Package ghpr pushes a single-file fix to a new branch on GitHub via the REST
// API: create a branch off the base ref and commit the patched file. It does NOT
// open a PR — it returns a compare URL you (or CI) can open the PR from. Client-
// side only: uses the caller's GitHub token (the CI's ambient GITHUB_TOKEN);
// nothing is sent to Appknox. Pure stdlib, no new dependency.
package ghpr

import (
	"bytes"
	"context"
	"encoding/base64"
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
	defaultAPIBase = "https://api.github.com"
	httpTimeout    = 60 * time.Second
	maxRespBytes   = 8 << 20 // cap any GitHub response (OOM guard)
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

// Change is the branch + single patched file + commit message to push.
type Change struct {
	Branch  string
	Path    string
	Content string
	Message string
}

// FileChange is one patched file (path + content + commit message).
type FileChange struct {
	Path    string
	Content string
	Message string
}

// PushBranch pushes a single patched file to a new branch (thin wrapper).
func PushBranch(ctx context.Context, cfg Config, ch Change) (string, error) {
	return PushFiles(ctx, cfg, ch.Branch, []FileChange{{Path: ch.Path, Content: ch.Content, Message: ch.Message}})
}

// PushFiles creates branch off the base ref and commits each patched file to it
// (one commit per file), returning a compare URL that pre-fills a PR. Idempotent:
// an existing branch is reused. It does not open the PR itself.
func PushFiles(ctx context.Context, cfg Config, branch string, files []FileChange) (string, error) {
	if cfg.Owner == "" || cfg.Repo == "" || cfg.Token == "" {
		return "", errors.New("ghpr: owner, repo, and token are required")
	}
	if len(files) == 0 {
		return "", errors.New("ghpr: no files to push")
	}
	base, err := resolveBase(ctx, cfg)
	if err != nil {
		return "", err
	}
	baseSHA, err := branchSHA(ctx, cfg, base)
	if err != nil {
		return "", err
	}
	if err := createBranch(ctx, cfg, branch, baseSHA); err != nil {
		return "", err
	}
	if err := commitFiles(ctx, cfg, branch, files); err != nil {
		return "", err
	}
	return compareURL(cfg, base, branch), nil
}

// resolveBase returns the configured base ref or the repo's default branch.
func resolveBase(ctx context.Context, cfg Config) (string, error) {
	if cfg.BaseRef != "" {
		return cfg.BaseRef, nil
	}
	return defaultBranch(ctx, cfg)
}

// commitFiles commits each file to the branch, one commit per file. On a re-run
// the file's current blob sha on the branch is used so the update is accepted.
func commitFiles(ctx context.Context, cfg Config, branch string, files []FileChange) error {
	for _, f := range files {
		fileSHA, err := currentFileSHA(ctx, cfg, f.Path, branch)
		if err != nil {
			return err
		}
		ch := Change{Branch: branch, Path: f.Path, Content: f.Content, Message: f.Message}
		if err := putFile(ctx, cfg, ch, fileSHA); err != nil {
			return err
		}
	}
	return nil
}

func defaultBranch(ctx context.Context, cfg Config) (string, error) {
	var out struct {
		DefaultBranch string `json:"default_branch"`
	}
	u := fmt.Sprintf("%s/repos/%s/%s", cfg.apiBase(), cfg.Owner, cfg.Repo)
	if err := cfg.do(ctx, http.MethodGet, u, nil, &out); err != nil {
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
	u := fmt.Sprintf("%s/repos/%s/%s/git/ref/heads/%s", cfg.apiBase(), cfg.Owner, cfg.Repo, url.PathEscape(ref))
	if err := cfg.do(ctx, http.MethodGet, u, nil, &out); err != nil {
		return "", err
	}
	if out.Object.SHA == "" {
		return "", fmt.Errorf("ghpr: no sha for base ref %q", ref)
	}
	return out.Object.SHA, nil
}

// createBranch creates the branch, treating an already-existing branch as success
// so re-runs are idempotent (the file is then committed on top of it).
func createBranch(ctx context.Context, cfg Config, branch, sha string) error {
	body := map[string]string{"ref": "refs/heads/" + branch, "sha": sha}
	u := fmt.Sprintf("%s/repos/%s/%s/git/refs", cfg.apiBase(), cfg.Owner, cfg.Repo)
	err := cfg.do(ctx, http.MethodPost, u, body, nil)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		return nil // reuse the existing branch
	}
	return err
}

// currentFileSHA returns the file's blob sha on ref (needed to update it), or ""
// when the file does not exist yet (a new file).
func currentFileSHA(ctx context.Context, cfg Config, path, ref string) (string, error) {
	var out struct {
		SHA string `json:"sha"`
	}
	u := contentsURL(cfg, path) + "?ref=" + url.QueryEscape(ref)
	if err := cfg.do(ctx, http.MethodGet, u, nil, &out); err != nil {
		if strings.Contains(err.Error(), "HTTP 404") {
			return "", nil
		}
		return "", err
	}
	return out.SHA, nil
}

func putFile(ctx context.Context, cfg Config, ch Change, fileSHA string) error {
	body := map[string]string{
		"message": ch.Message,
		"content": base64.StdEncoding.EncodeToString([]byte(ch.Content)),
		"branch":  ch.Branch,
	}
	if fileSHA != "" {
		body["sha"] = fileSHA
	}
	return cfg.do(ctx, http.MethodPut, contentsURL(cfg, ch.Path), body, nil)
}

// contentsURL builds the Contents API URL with each path segment escaped.
func contentsURL(cfg Config, path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return fmt.Sprintf("%s/repos/%s/%s/contents/%s", cfg.apiBase(), cfg.Owner, cfg.Repo, strings.Join(segs, "/"))
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
	if out == nil {
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
