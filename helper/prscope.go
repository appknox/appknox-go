package helper

import (
	"context"
	"errors"
	"os"

	"github.com/appknox/appknox-go/ghpr"
)

// scopePR restricts a run to the files changed in the originating pull request.
const scopePR = "pr"

// applyScope narrows the located paths to the developer's own changes when the
// run is PR-scoped, returning the excluded ones as advisories.
//
// Scoping defaults to the PR whenever --pr-number is given: fixing files the
// developer did not touch in this PR is the surprising behaviour, so it has to
// be asked for explicitly with --scope repo.
func (s fixSession) applyScope(ctx context.Context, located []string) (inScope, advisory []string, err error) {
	if !s.opts.prScoped() || len(located) == 0 {
		return located, nil, nil
	}
	changed, err := s.d.prFiles(ctx, s.opts)
	if err != nil {
		return nil, nil, err
	}
	inScope, advisory = scopeToPR(located, changed)
	return inScope, advisory, nil
}

// prScoped reports whether this run is limited to the pull request's files.
func (o AutofixOptions) prScoped() bool {
	if o.PRNumber <= 0 {
		return false
	}
	return o.Scope == "" || o.Scope == scopePR
}

// fetchPRFiles lists the files changed in the originating pull request.
func fetchPRFiles(ctx context.Context, opts AutofixOptions) ([]string, error) {
	owner, name, err := splitRepo(opts.Repo)
	if err != nil {
		return nil, errors.New("--scope pr needs --repo owner/name")
	}
	token := firstNonEmpty(opts.GithubToken, os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return nil, errors.New("--scope pr needs a GitHub token (--github-token or GITHUB_TOKEN)")
	}
	return ghpr.ListPRFiles(ctx,
		ghpr.Config{Owner: owner, Repo: name, Token: token}, opts.PRNumber)
}
