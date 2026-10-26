package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// githubClient is a minimal GitHub REST client using the CI token
// (GITHUB_TOKEN). The token never leaves the CI runner.
type githubClient struct {
	apiURL string
	repo   string // owner/repo
	token  string
	http   *http.Client
}

type githubPR struct {
	Number    int        `json:"number"`
	HTMLURL   string     `json:"html_url"`
	State     string     `json:"state"`
	MergedAt  *time.Time `json:"merged_at"`
	CreatedAt time.Time  `json:"created_at"`
	Head      struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"head"`
}

type githubAPIError struct {
	StatusCode int
	Message    string `json:"message"`
	Errors     []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (e *githubAPIError) Error() string {
	parts := []string{e.Message}
	for _, item := range e.Errors {
		if item.Message != "" {
			parts = append(parts, item.Message)
		}
	}
	return fmt.Sprintf("GitHub API %d: %s", e.StatusCode, strings.Join(parts, "; "))
}

func newGitHubClient(apiURL, repo, token string) *githubClient {
	return &githubClient{apiURL: strings.TrimRight(apiURL, "/"), repo: repo, token: token,
		http: &http.Client{Timeout: 60 * time.Second}}
}

func (g *githubClient) do(ctx context.Context, method, path string, body, out interface{}) (int, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.apiURL+path, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &githubAPIError{StatusCode: resp.StatusCode}
		_ = json.Unmarshal(data, apiErr)
		return resp.StatusCode, apiErr
	}
	if out != nil && len(data) > 0 {
		return resp.StatusCode, json.Unmarshal(data, out)
	}
	return resp.StatusCode, nil
}

// latestKnoxFixerPR returns the PR to use for head → base: the newest open one
// (warning if there are several), else the newest of any state. nil if none.
func (g *githubClient) latestKnoxFixerPR(ctx context.Context, head, base string) (*githubPR, int, error) {
	owner := strings.SplitN(g.repo, "/", 2)[0]
	query := url.Values{}
	query.Set("head", owner+":"+head)
	query.Set("base", base)
	query.Set("state", "all")
	query.Set("sort", "created")
	query.Set("direction", "desc")
	query.Set("per_page", "30")
	var prs []githubPR
	if _, err := g.do(ctx, "GET", "/repos/"+g.repo+"/pulls?"+query.Encode(), nil, &prs); err != nil {
		return nil, 0, err
	}
	// Only exact head matches (GitHub matches by owner:ref already).
	var matching []githubPR
	for _, pr := range prs {
		if pr.Head.Ref == head {
			matching = append(matching, pr)
		}
	}
	if len(matching) == 0 {
		return nil, 0, nil
	}
	sort.SliceStable(matching, func(i, j int) bool { return matching[i].CreatedAt.After(matching[j].CreatedAt) })
	openCount := 0
	var newestOpen *githubPR
	for i := range matching {
		if matching[i].State == "open" {
			openCount++
			if newestOpen == nil {
				newestOpen = &matching[i]
			}
		}
	}
	if newestOpen != nil {
		return newestOpen, openCount, nil
	}
	return &matching[0], 0, nil
}

func (g *githubClient) branchExists(ctx context.Context, branch string) (bool, error) {
	status, err := g.do(ctx, "GET", "/repos/"+g.repo+"/branches/"+url.PathEscape(branch), nil, nil)
	if status == http.StatusNotFound {
		return false, nil
	}
	return err == nil, err
}

func (g *githubClient) createBranch(ctx context.Context, branch, sha string) error {
	_, err := g.do(ctx, "POST", "/repos/"+g.repo+"/git/refs",
		map[string]string{"ref": "refs/heads/" + branch, "sha": sha}, nil)
	return err
}

func (g *githubClient) deleteBranch(ctx context.Context, branch string) error {
	status, err := g.do(ctx, "DELETE", "/repos/"+g.repo+"/git/refs/heads/"+branch, nil, nil)
	if status == http.StatusNotFound || status == http.StatusUnprocessableEntity {
		return nil // already gone
	}
	return err
}

func (g *githubClient) reopenPR(ctx context.Context, number int) error {
	_, err := g.do(ctx, "PATCH", fmt.Sprintf("/repos/%s/pulls/%d", g.repo, number),
		map[string]string{"state": "open"}, nil)
	return err
}

func (g *githubClient) createPR(ctx context.Context, head, base, title, body string) (*githubPR, error) {
	var pr githubPR
	_, err := g.do(ctx, "POST", "/repos/"+g.repo+"/pulls", map[string]interface{}{
		"title": title, "head": head, "base": base, "body": body, "draft": false,
	}, &pr)
	if err != nil {
		return nil, err
	}
	return &pr, nil
}

func (g *githubClient) updatePR(ctx context.Context, number int, title, body string) error {
	_, err := g.do(ctx, "PATCH", fmt.Sprintf("/repos/%s/pulls/%d", g.repo, number),
		map[string]string{"title": title, "body": body}, nil)
	return err
}

// prCreateHint explains the common PR-creation failures.
func prCreateHint(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not permitted to create or approve pull requests"):
		return "enable \"Allow GitHub Actions to create and approve pull requests\" in the repository settings"
	case strings.Contains(msg, "403"), strings.Contains(msg, "resource not accessible"):
		return "the workflow needs `permissions: contents: write, pull-requests: write`"
	}
	return ""
}
