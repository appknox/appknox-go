package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/ghpr"
)

const (
	autofixBranchPrefix = "appknox-autofix/"
	// GitHub refs are limited to ~244 bytes including "refs/heads/".
	gitHubRefMaxBytes = 244
	refsHeadsPrefix   = "refs/heads/"
)

var (
	errNeedHeadRef = errors.New("autofix needs --head-ref (or GITHUB_HEAD_REF / GITHUB_REF refs/heads/…)")
	errForkPR      = errors.New("autofix does not support fork PRs (cannot push the head)")
	disallowedHead = regexp.MustCompile(`[^A-Za-z0-9._/-]+`)
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
	if forkPRFromCI() {
		return Delivery{}, errForkPR
	}
	owner, name, err := splitRepo(opts.Repo)
	if err != nil {
		return Delivery{}, errors.New("autofix needs a CI repo (GITHUB_REPOSITORY) to push the fix branch")
	}
	token := firstNonEmpty(opts.GithubToken, os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return Delivery{}, errors.New("autofix needs a GitHub token (--github-token or GITHUB_TOKEN) to push the fix branch")
	}
	branch, err := prBranch(opts.HeadRef)
	if err != nil {
		return Delivery{}, err
	}
	files := make([]ghpr.FileChange, len(patches))
	for i, p := range patches {
		files[i] = ghpr.FileChange{Path: p.Path, Content: p.Content}
	}
	cfg := ghpr.Config{Owner: owner, Repo: name, BaseRef: opts.Ref, Token: token, APIBase: os.Getenv("GITHUB_API_URL")}
	res, err := ghpr.PushFiles(ctx, cfg, branch, files, prTitle(opts))
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
	if opts.HeadRef != "" {
		return "fix(autofix): " + strings.TrimSpace(opts.HeadRef)
	}
	return "fix(autofix): security findings"
}

func prBody(opts AutofixOptions, patches []filePatch) string {
	var b strings.Builder
	b.WriteString("Appknox autofix generated this change from a scan.\n\n")
	if opts.FileID > 0 {
		fmt.Fprintf(&b, "- File id (this run): `%d`\n", opts.FileID)
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

// prBranch is a stable GitHub head for every file id on the same feature branch.
func prBranch(headRef string) (string, error) {
	feature, err := sanitizeFeature(headRef)
	if err != nil {
		return "", err
	}
	return capGitRef(autofixBranchPrefix+feature, headRef), nil
}

func sanitizeFeature(headRef string) (string, error) {
	headRef = strings.TrimSpace(headRef)
	if headRef == "" {
		return "", errNeedHeadRef
	}
	replaced := disallowedHead.ReplaceAllString(headRef, "-")
	var kept []string
	for _, part := range strings.Split(replaced, "/") {
		part = strings.Trim(part, ".")
		if part == "" || part == "." || part == ".." {
			continue
		}
		for strings.Contains(part, "..") {
			part = strings.ReplaceAll(part, "..", ".")
		}
		part = strings.Trim(part, ".")
		if part == "" {
			continue
		}
		kept = append(kept, part)
	}
	out := strings.Join(kept, "/")
	if out == "" {
		return "", fmt.Errorf("illegal feature branch name %q", headRef)
	}
	return out, nil
}

// capGitRef truncates a branch name to GitHub's ref limit, keeping uniqueness
// with a short hash of the original feature name.
func capGitRef(branch, original string) string {
	max := gitHubRefMaxBytes - len(refsHeadsPrefix)
	if len(branch) <= max {
		return branch
	}
	sum := sha256.Sum256([]byte(original))
	suffix := "-" + hex.EncodeToString(sum[:4])
	keep := max - len(suffix)
	if keep < 1 {
		return suffix[1:]
	}
	truncated := strings.TrimRight(branch[:keep], "/.-")
	if truncated == "" {
		truncated = strings.TrimRight(autofixBranchPrefix, "/")
	}
	return truncated + suffix
}

// commitMessage is a conventional-commit subject for the fix.
func commitMessage(p filePatch) string {
	name := p.Finding
	if name == "" {
		name = "security finding"
	}
	return fmt.Sprintf("fix(autofix): %s in %s", name, filepath.Base(p.Path))
}
