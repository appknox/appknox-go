package ghpr

import (
	"context"
	"fmt"
	"net/url"
)

// Pull-request operations, kept separate from branch pushing.
//
// These back two agreed behaviours:
//
//   - --scope pr: a fix may only touch files the developer changed in THIS pull
//     request. ListPRFiles supplies that set; a located file outside it becomes
//     an advisory rather than a silent edit somewhere the developer wasn't
//     looking.
//   - delivery as a DRAFT pull request, so CI runs and a human reviews before
//     anything is mergeable.

// prPageSize is GitHub's maximum page size for list endpoints.
const prPageSize = 100

// PullRequest describes the pull request to open.
type PullRequest struct {
	Branch string // head branch holding the fix
	Base   string // base branch to merge into; empty = repo default
	Title  string
	Body   string
}

// prFile is one entry of the pull-request files listing.
type prFile struct {
	Filename string `json:"filename"`
}

// pullRef identifies an existing pull request.
type pullRef struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

// ListPRFiles returns every repo-relative path changed in a pull request.
//
// Paginates until a short page arrives, so a large PR does not silently
// truncate -- an incomplete list would wrongly exclude files from --scope pr and
// skip fixes the developer expected.
func ListPRFiles(ctx context.Context, cfg Config, number int) ([]string, error) {
	var paths []string
	for page := 1; ; page++ {
		endpoint := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/files?per_page=%d&page=%d",
			cfg.apiBase(), cfg.Owner, cfg.Repo, number, prPageSize, page)

		var batch []prFile
		if err := cfg.do(ctx, "GET", endpoint, nil, &batch); err != nil {
			return nil, fmt.Errorf("ghpr: listing files for PR %d: %w", number, err)
		}
		for _, f := range batch {
			paths = append(paths, f.Filename)
		}
		if len(batch) < prPageSize {
			return paths, nil
		}
	}
}

// OpenDraftPR opens a draft pull request for the fix branch and returns its URL.
//
// Draft is deliberate: the fix is a proposal. It must run CI and be reviewed
// before it can be merged, never land unattended.
func OpenDraftPR(ctx context.Context, cfg Config, pr PullRequest) (string, error) {
	base := pr.Base
	if base == "" {
		var err error
		if base, err = defaultBranch(ctx, cfg); err != nil {
			return "", err
		}
	}
	body := map[string]any{
		"title": pr.Title,
		"head":  pr.Branch,
		"base":  base,
		"body":  pr.Body,
		"draft": true,
	}
	var created pullRef
	endpoint := fmt.Sprintf("%s/repos/%s/%s/pulls", cfg.apiBase(), cfg.Owner, cfg.Repo)
	if err := cfg.do(ctx, "POST", endpoint, body, &created); err != nil {
		return "", fmt.Errorf("ghpr: opening draft PR for %s: %w", pr.Branch, err)
	}
	return created.HTMLURL, nil
}

// FindOpenPR returns the URL of an open pull request for the given head branch,
// or "" when there is none.
//
// Re-running autofix for the same finding reuses the branch, so without this a
// second run would try to open a duplicate PR for it.
func FindOpenPR(ctx context.Context, cfg Config, branch string) (string, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/pulls?state=open&head=%s",
		cfg.apiBase(), cfg.Owner, cfg.Repo,
		url.QueryEscape(cfg.Owner+":"+branch))

	var open []pullRef
	if err := cfg.do(ctx, "GET", endpoint, nil, &open); err != nil {
		return "", fmt.Errorf("ghpr: looking up an open PR for %s: %w", branch, err)
	}
	if len(open) == 0 {
		return "", nil
	}
	return open[0].HTMLURL, nil
}
