package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/appknox/appknox-go/agent"
	"github.com/appknox/appknox-go/ghfetch"
)

// AutofixOptions carries the flags for the client-side autofix locate flow.
type AutofixOptions struct {
	Repo        string // GitHub owner/name to auto-fetch
	Ref         string // git ref (branch/tag/sha); empty = default branch
	RepoPath    string // already-checked-out repo (alternative to Repo)
	Finding     string // scan finding detail (required)
	ClassHint   string // class/symbol hint (optional)
	FixURL      string // Appknox fix-service/gateway base URL
	FixToken    string // scoped fix-service token
	GithubToken string // GitHub token for the --repo fetch
}

// locateFn is the locate seam (agent.LocateFile) so runAutofix is testable
// without a live model call.
type locateFn func(ctx context.Context, cfg agent.Config, req agent.Request) (string, error)

// ProcessAutofix runs the locate flow and exits non-zero on error (CLI entry).
func ProcessAutofix(opts AutofixOptions) {
	path, err := runAutofix(context.Background(), opts, agent.LocateFile)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	if path == "" {
		fmt.Println("No source file located for this finding (advisory only).")
		return
	}
	fmt.Println("Located file to fix:", path)
}

// runAutofix resolves the repo (local checkout or GitHub fetch), then locates the
// single file to fix. The repo stays local; only model turns leave, via the gateway.
func runAutofix(ctx context.Context, opts AutofixOptions, locate locateFn) (string, error) {
	if opts.Finding == "" {
		return "", errors.New("--finding is required")
	}
	token := firstNonEmpty(opts.FixToken, os.Getenv("APPKNOX_AUTOFIX_FIX_TOKEN"))
	if token == "" {
		return "", errors.New("fix-service token required (--fix-token or APPKNOX_AUTOFIX_FIX_TOKEN)")
	}
	root, cleanup, err := resolveRepoRoot(ctx, opts)
	if err != nil {
		return "", err
	}
	defer cleanup()

	cfg := agent.Config{FixURL: firstNonEmpty(opts.FixURL, "http://localhost:8100"), Token: token}
	req := agent.Request{RepoRoot: root, ClassHint: opts.ClassHint, Finding: opts.Finding}
	return locate(ctx, cfg, req)
}

// resolveRepoRoot returns the repo root and a cleanup func: a local --repo-path as
// is, or a freshly fetched GitHub tarball (cleanup removes the temp dir).
func resolveRepoRoot(ctx context.Context, opts AutofixOptions) (string, func(), error) {
	if opts.RepoPath != "" {
		return opts.RepoPath, func() {}, nil
	}
	if opts.Repo == "" {
		return "", nil, errors.New("provide --repo owner/name (auto-fetch) or --repo-path <dir>")
	}
	owner, name, err := splitRepo(opts.Repo)
	if err != nil {
		return "", nil, err
	}
	return ghfetch.FetchTarball(ctx, ghfetch.Config{
		Owner: owner, Repo: name, Ref: opts.Ref,
		Token: firstNonEmpty(opts.GithubToken, os.Getenv("GITHUB_TOKEN")),
	})
}

// splitRepo parses an "owner/name" repo spec.
func splitRepo(spec string) (string, string, error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid --repo %q, expected owner/name", spec)
	}
	return parts[0], parts[1], nil
}

// firstNonEmpty returns a if non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
