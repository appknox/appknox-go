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

	"github.com/appknox/appknox-go/ghpr"
)

// deliverBranch pushes all patched files to one branch and opens a DRAFT pull
// request for them, returning the PR URL.
//
// Draft is the point: the fix is a proposal. It runs CI and gets reviewed before
// it can merge. If a PR for this branch is already open -- a re-run of the same
// finding -- that one is reused rather than opening a duplicate.
func deliverBranch(ctx context.Context, opts AutofixOptions, patches []filePatch, inputs FindingInputs) (string, error) {
	owner, name, err := splitRepo(opts.Repo)
	if err != nil {
		return "", errors.New("--push-branch needs --repo owner/name")
	}
	token := firstNonEmpty(opts.GithubToken, os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return "", errors.New("--push-branch needs a GitHub token (--github-token or GITHUB_TOKEN)")
	}
	// The fix belongs beside the work that produced it, so it targets the source
	// feature branch rather than the repository default.
	source := SourceBranch(opts.SourceBranch)
	base := firstNonEmpty(source, opts.Ref)
	cfg := ghpr.Config{Owner: owner, Repo: name, BaseRef: base, Token: token}

	files := make([]ghpr.FileChange, len(patches))
	for i, p := range patches {
		files[i] = ghpr.FileChange{Path: p.Path, Content: p.Content, Message: commitMessage(inputs, p.Path)}
	}
	branch := prBranch(source, opts.PRNumber, opts.AnalysisID, patches[0].Path)
	if _, err := ghpr.PushFiles(ctx, cfg, branch, files); err != nil {
		return "", err
	}

	existing, err := ghpr.FindOpenPR(ctx, cfg, branch)
	if err != nil {
		return "", err
	}
	if existing != "" {
		return existing, nil
	}
	return ghpr.OpenDraftPR(ctx, cfg, ghpr.PullRequest{
		Branch: branch, Base: base,
		Title: prTitle(inputs),
		Body:  prBody(inputs, patches),
	})
}

// prBranch is a stable branch name for the fix.
//
// Keyed on the SOURCE FEATURE BRANCH where possible: one active autofix branch
// and one draft PR per feature branch, so a second scan of the same branch
// updates them rather than opening another. Keying on the scan or the analysis
// instead is how a busy branch ends up with a dozen remediation PRs.
//
// The older analysis- and hash-based names remain as fallbacks for runs outside
// CI, where no branch context exists.
func prBranch(sourceBranch string, prNumber, analysisID int, path string) string {
	if name := autofixBranchFor(sourceBranch); name != "" {
		return name
	}
	switch {
	case prNumber > 0 && analysisID > 0:
		return fmt.Sprintf("bugfix/appknox-autofix-%d-%d", prNumber, analysisID)
	case analysisID > 0:
		return fmt.Sprintf("appknox-autofix/analysis-%d", analysisID)
	}
	sum := sha256.Sum256([]byte(path))
	return "appknox-autofix/fix-" + hex.EncodeToString(sum[:])[:10]
}

// commitMessage is a conventional-commit subject for the fix.
func commitMessage(inputs FindingInputs, path string) string {
	return fmt.Sprintf("fix(autofix): %s in %s", findingName(inputs), filepath.Base(path))
}

// prTitle names the draft PR after the finding it addresses.
func prTitle(inputs FindingInputs) string {
	return "Appknox Autofix: " + findingName(inputs)
}

// findingName is the finding's name, or a neutral fallback.
func findingName(inputs FindingInputs) string {
	if inputs.Finding == "" {
		return "security finding"
	}
	return inputs.Finding
}

// prBody explains what was changed and, crucially, how far it was verified.
//
// The verification state is stated plainly rather than implied: a reviewer must
// not read a tidy diff as evidence that the fix was checked.
func prBody(inputs FindingInputs, patches []filePatch) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Automated fix for **%s**.\n\n", findingName(inputs))

	b.WriteString("Files changed:\n")
	for _, p := range patches {
		fmt.Fprintf(&b, "- `%s`\n", p.Path)
	}
	if len(inputs.Criteria) > 0 {
		b.WriteString("\nChecked against KnoxIQ's verification criteria:\n")
		for _, c := range inputs.Criteria {
			fmt.Fprintf(&b, "- %s\n", c)
		}
	} else {
		b.WriteString("\n> **Not verified.** KnoxIQ recorded no verification criteria " +
			"for this finding, so the patch could not be machine-checked.\n")
	}
	b.WriteString("\nOpened as a draft: review and let CI run before merging.\n")
	return b.String()
}

// scopeToPR keeps only the located paths the developer changed in this pull
// request, returning the rest as advisories.
//
// The requirement is to apply suggested fixes only to the files modified by the
// developer. A located file outside the PR is reported rather than edited, so
// autofix never quietly changes code the reviewer is not looking at here.
func scopeToPR(located, prFiles []string) (inScope, advisory []string) {
	changed := make(map[string]bool, len(prFiles))
	for _, f := range prFiles {
		changed[f] = true
	}
	for _, path := range located {
		if changed[path] {
			inScope = append(inScope, path)
		} else {
			advisory = append(advisory, path)
		}
	}
	return inScope, advisory
}
