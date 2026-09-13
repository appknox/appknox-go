package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

// deliverBranch pushes patched files to a new branch, opens a GitHub PR, and
// returns the PR URL for Mycroft's AutofixPR row.
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
	cfg := ghpr.Config{Owner: owner, Repo: name, BaseRef: opts.Ref, Token: token, APIBase: os.Getenv("GITHUB_API_URL")}
	res, err := ghpr.PushFiles(ctx, cfg, prBranch(opts.AnalysisID, patches[0].Path), files)
	if err != nil {
		return Delivery{}, err
	}
	prURL, err := ghpr.OpenPullRequest(ctx, cfg, res.Base, res.Branch, prTitle(inputs, opts.AnalysisID), prBody(opts, inputs, patches))
	if err != nil {
		return Delivery{}, fmt.Errorf("pushed branch %s but failed to open a pull request: %w\nGITHUB_TOKEN cannot open PRs unless the workflow has pull-requests: write and the repo allows Actions to create PRs (Settings → Actions → General). Or set APPKNOX_GITHUB_TOKEN to a PAT with repo scope", res.Branch, err)
	}
	return Delivery{URL: prURL, Branch: res.Branch, Base: res.Base, CommitSHA: res.CommitSHA}, nil
}

func prTitle(inputs FindingInputs, analysisID int) string {
	name := inputs.Finding
	if name == "" {
		name = "security finding"
	}
	if analysisID > 0 {
		return fmt.Sprintf("fix(autofix): %s (analysis %d)", name, analysisID)
	}
	return fmt.Sprintf("fix(autofix): %s", name)
}

func prBody(opts AutofixOptions, inputs FindingInputs, patches []filePatch) string {
	var b strings.Builder
	b.WriteString("Appknox autofix generated this change from a scan finding.\n\n")
	if opts.AnalysisID > 0 {
		fmt.Fprintf(&b, "- Analysis: `%d`\n", opts.AnalysisID)
	}
	if opts.FileID > 0 {
		fmt.Fprintf(&b, "- File id: `%d`\n", opts.FileID)
	}
	if inputs.Finding != "" {
		fmt.Fprintf(&b, "- Finding: %s\n", inputs.Finding)
	}
	if len(patches) > 0 {
		b.WriteString("- Patched files:\n")
		for _, p := range patches {
			fmt.Fprintf(&b, "  - `%s`\n", p.Path)
		}
	}
	return b.String()
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
