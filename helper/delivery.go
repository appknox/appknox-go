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
// returns the PR URL for Mycroft's KnoxIQ AutofixPR row.
func deliverBranch(ctx context.Context, opts AutofixOptions, patches []filePatch) (Delivery, error) {
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
		files[i] = ghpr.FileChange{Path: p.Path, Content: p.Content}
	}
	cfg := ghpr.Config{Owner: owner, Repo: name, BaseRef: opts.Ref, Token: token, APIBase: os.Getenv("GITHUB_API_URL")}
	fallback := ""
	if len(patches) > 0 {
		fallback = patches[0].Path
	}
	res, err := ghpr.PushFiles(ctx, cfg, prBranch(opts.FileID, fallback), files, prTitle(opts))
	if err != nil {
		return Delivery{}, err
	}
	prURL, err := ghpr.OpenPullRequest(ctx, cfg, res.Base, res.Branch, prTitle(opts), prBody(opts, patches))
	if err != nil {
		return Delivery{}, fmt.Errorf("pushed branch %s but failed to open a pull request: %w\nGITHUB_TOKEN cannot open PRs unless the workflow has pull-requests: write and the repo allows Actions to create PRs (Settings → Actions → General). Or set APPKNOX_GITHUB_TOKEN to a PAT with repo scope", res.Branch, err)
	}
	return Delivery{URL: prURL, Branch: res.Branch, Base: res.Base, CommitSHA: res.CommitSHA}, nil
}

func prTitle(opts AutofixOptions) string {
	if opts.FileID > 0 {
		return fmt.Sprintf("fix(autofix): Appknox scan (file %d)", opts.FileID)
	}
	return "fix(autofix): security findings"
}

func prBody(opts AutofixOptions, patches []filePatch) string {
	var b strings.Builder
	b.WriteString("Appknox autofix generated this change from a scan.\n\n")
	if opts.FileID > 0 {
		fmt.Fprintf(&b, "- File id: `%d`\n", opts.FileID)
	}
	findings := uniqueFindings(patches)
	if len(findings) > 0 {
		b.WriteString("- Findings:\n")
		for _, name := range findings {
			fmt.Fprintf(&b, "  - %s\n", name)
		}
	}
	if len(patches) > 0 {
		b.WriteString("- Patched files:\n")
		for _, p := range patches {
			fmt.Fprintf(&b, "  - `%s`\n", p.Path)
		}
	}
	return b.String()
}

func uniqueFindings(patches []filePatch) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range patches {
		if p.Finding == "" || seen[p.Finding] {
			continue
		}
		seen[p.Finding] = true
		out = append(out, p.Finding)
	}
	return out
}

// reportAutofixPR POSTs the pushed branch to KnoxIQ so the dashboard can list it.
// Skipped when --file-id is not set (manual --finding has nothing to attach to).
func reportAutofixPR(ctx context.Context, opts AutofixOptions, d Delivery, patches []filePatch) error {
	return reportAutofixPRWith(ctx, getClient(), opts, d, patches)
}

func reportAutofixPRWith(ctx context.Context, client *appknox.Client, opts AutofixOptions, d Delivery, patches []filePatch) error {
	if opts.FileID <= 0 {
		return nil
	}
	_, _, err := client.KnoxIQ.CreateAutofixPR(ctx, opts.FileID, buildAutofixPR(opts, d, patches))
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
		Repo:         opts.Repo,
		BaseBranch:   base,
		Branch:       d.Branch,
		PRURL:        d.URL,
		CommitSHA:    d.CommitSHA,
		PatchedFiles: paths,
	}
}

// prBranch is a stable branch name for the file's fix PR.
func prBranch(fileID int, path string) string {
	if fileID > 0 {
		return fmt.Sprintf("appknox-autofix/analysis-%d", fileID)
	}
	sum := sha256.Sum256([]byte(path))
	return "appknox-autofix/fix-" + hex.EncodeToString(sum[:])[:10]
}

// commitMessage is a conventional-commit subject for the fix.
func commitMessage(p filePatch) string {
	name := p.Finding
	if name == "" {
		name = "security finding"
	}
	return fmt.Sprintf("fix(autofix): %s in %s", name, filepath.Base(p.Path))
}
