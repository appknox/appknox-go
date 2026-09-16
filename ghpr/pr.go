// Package ghpr pushes a single-file fix to a new branch on GitHub via the REST
// API: create a branch off the base ref and commit the patched file. It does NOT
// open a PR — it returns a compare URL you (or CI) can open the PR from. Client-
// side only: uses the caller's GitHub token (the CI's ambient GITHUB_TOKEN);
// nothing is sent to Appknox. Pure stdlib, no new dependency.
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

// FileChange is one patched file (path + content + commit message).
//
// Message survives for per-file provenance in the report, but every file now
// lands in ONE commit, so PushFiles takes the commit subject separately.
type FileChange struct {
	Path    string
	Content string
	Message string
}

// PushFiles creates branch off the base ref and writes every patched file in
// ONE commit, returning the compare URL and the commit SHA. Idempotent: an
// existing branch is reused and the commit is parented on its tip. It does not
// open the PR itself.
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
