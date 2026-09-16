package appknox

import (
	"context"
	"fmt"
)

// Delivered autofix pull requests, recorded back on Appknox.
//
// Ported from feat/autofix-cli (0cbce27). Without this the platform has no
// idea a fix was ever proposed: the pull request exists on GitHub and the
// finding stays open on Appknox, with nothing linking the two. Recording it is
// what lets the dashboard say "a fix is waiting" rather than only "still
// vulnerable".

// AutofixPR is a delivered autofix GitHub PR for one scanned file.
type AutofixPR struct {
	ID           int      `json:"id,omitempty"`
	File         int      `json:"file,omitempty"`
	Repo         string   `json:"repo"`
	BaseBranch   string   `json:"base_branch"`
	Branch       string   `json:"branch"`
	PRURL        string   `json:"pr_url"`
	CommitSHA    string   `json:"commit_sha,omitempty"`
	PatchedFiles []string `json:"patched_files,omitempty"`
}

// CreateAutofixPR records a delivered autofix: upserts the PR, appends a commit.
//
// Keyed per FILE, matching the branch scheme: one scan produces one branch,
// one pull request and one record, so a re-run updates that record rather than
// accumulating duplicates.
func (s *FilesService) CreateAutofixPR(ctx context.Context, fileID int, pr *AutofixPR) (*AutofixPR, *Response, error) {
	u := fmt.Sprintf("api/v2/files/%d/autofix_prs", fileID)
	req, err := s.client.NewRequest("POST", u, pr)
	if err != nil {
		return nil, nil, err
	}
	var out AutofixPR
	resp, err := s.client.Do(ctx, req, &out)
	return &out, resp, err
}
