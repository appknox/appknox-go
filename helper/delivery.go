package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/ghpr"
)

// Delivery is the GitHub push outcome recorded on Appknox after autofix.
type Delivery struct {
	URL       string
	Branch    string
	Base      string
	CommitSHA string
}

// deliverBranch pushes all patched files to one new branch on GitHub (no PR
// opened) and returns a compare URL.
func deliverBranch(ctx context.Context, opts AutofixOptions, patches []filePatch, inputs FindingInputs) (Delivery, error) {
	opts = applyCIDefaults(opts)
	owner, name, err := splitRepo(opts.Repo)
	if err != nil {
		return Delivery{}, errors.New("autofix needs a CI repo (GITHUB_REPOSITORY) to push the fix branch")
	}
	token := firstNonEmpty(opts.GithubToken, os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return Delivery{}, errors.New("autofix needs a GitHub token (--github-token or GITHUB_TOKEN) to push the fix branch")
	}
	files := make([]ghpr.FileChange, len(patches))
	for i, p := range patches {
		files[i] = ghpr.FileChange{Path: p.Path, Content: p.Content, Message: commitMessage(inputs, p.Path)}
	}
	res, err := ghpr.PushFiles(ctx,
		ghpr.Config{Owner: owner, Repo: name, BaseRef: opts.Ref, Token: token},
		prBranch(opts.AnalysisID, patches[0].Path), files)
	if err != nil {
		return Delivery{}, err
	}
	return Delivery{URL: res.URL, Branch: res.Branch, Base: res.Base, CommitSHA: res.CommitSHA}, nil
}

// reportAutofixPR POSTs the pushed branch to Mycroft so the dashboard can list it.
// Skipped when --file-id/--analysis-id are not set (manual --finding has nothing to attach to).
func reportAutofixPR(ctx context.Context, opts AutofixOptions, d Delivery, patches []filePatch) error {
	return reportAutofixPRWith(ctx, getClient(), opts, d, patches)
}

func reportAutofixPRWith(ctx context.Context, client *appknox.Client, opts AutofixOptions, d Delivery, patches []filePatch) error {
	if opts.FileID <= 0 || opts.AnalysisID <= 0 {
		return nil
	}
	_, _, err := client.Files.CreateAutofixPR(ctx, opts.FileID, buildAutofixPR(opts, d, patches))
	return err
}

func buildAutofixPR(opts AutofixOptions, d Delivery, patches []filePatch) *appknox.AutofixPR {
	paths := make([]string, len(patches))
	for i, p := range patches {
		paths[i] = p.Path
	}
	base := d.Base
	if base == "" {
		base = opts.Ref
	}
	return &appknox.AutofixPR{
		Analysis:     opts.AnalysisID,
		Repo:         opts.Repo,
		BaseBranch:   base,
		Branch:       d.Branch,
		PRURL:        d.URL,
		CommitSHA:    d.CommitSHA,
		SourcePR:     sourcePRFromCI(),
		PatchedFiles: paths,
	}
}

// prBranch is a stable branch name for the fix.
func prBranch(analysisID int, path string) string {
	if analysisID > 0 {
		return fmt.Sprintf("appknox-autofix/analysis-%d", analysisID)
	}
	sum := sha256.Sum256([]byte(path))
	return "appknox-autofix/fix-" + hex.EncodeToString(sum[:])[:10]
}

// commitMessage is a conventional-commit subject for the fix.
func commitMessage(inputs FindingInputs, path string) string {
	name := inputs.Finding
	if name == "" {
		name = "security finding"
	}
	return fmt.Sprintf("fix(autofix): %s in %s", name, filepath.Base(path))
}
