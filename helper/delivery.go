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
	// Base comes from the pipeline (applyCIDefaults): GITHUB_BASE_REF on a
	// pull_request job, else the branch from GITHUB_REF, else empty, which
	// leaves ghpr to resolve the repository's default branch.
	base := opts.Ref
	cfg := ghpr.Config{Owner: owner, Repo: name, BaseRef: base, Token: token}

	files := make([]ghpr.FileChange, len(patches))
	for i, p := range patches {
		files[i] = ghpr.FileChange{Path: p.Path, Content: p.Content, Message: commitMessage(inputs, p.Path)}
	}
	branch := prBranch(opts.FileID, patches[0].Path)
	res, err := ghpr.PushFiles(ctx, cfg, branch, files, commitMessage(inputs, patches[0].Path))
	if err != nil {
		return "", err
	}
	prURL, err := openOrReusePR(ctx, cfg, branch, res.Base, inputs, patches)
	if err != nil {
		return "", err
	}
	// Record the delivery on Appknox. A failure here is reported but does not
	// fail the run: the pull request exists and is the thing that matters, so
	// losing the link is a reporting gap, not a reason to discard a delivered
	// fix the developer can already see.
	if err := reportAutofixPR(ctx, opts, res, prURL, patches); err != nil {
		fmt.Printf("   !! pushed %s but failed to record it on Appknox: %v\n", branch, err)
	}
	return prURL, nil
}

// openOrReusePR returns the existing open PR for the branch, else opens one.
func openOrReusePR(ctx context.Context, cfg ghpr.Config, branch, base string,
	inputs FindingInputs, patches []filePatch) (string, error) {
	existing, err := ghpr.FindOpenPR(ctx, cfg, branch)
	if err != nil {
		return "", err
	}
	if existing != "" {
		return existing, nil
	}
	return ghpr.OpenPR(ctx, cfg, ghpr.PullRequest{
		Branch: branch, Base: base,
		Title: prTitle(inputs),
		Body:  prBody(inputs, patches),
	})
}

// reportAutofixPR links the delivered pull request back to the scanned file,
// so the platform can show that a fix is waiting rather than only that the
// finding is still open.
//
// Skipped without a file id: a manual --finding run has no scan to attach to.
func reportAutofixPR(ctx context.Context, opts AutofixOptions,
	res ghpr.Result, prURL string, patches []filePatch) error {
	if opts.FileID <= 0 {
		return nil
	}
	paths := make([]string, len(patches))
	for i, p := range patches {
		paths[i] = p.Path
	}
	_, _, err := getClient().Files.CreateAutofixPR(ctx, opts.FileID, &appknox.AutofixPR{
		Repo:         opts.Repo,
		BaseBranch:   res.Base,
		Branch:       res.Branch,
		PRURL:        prURL,
		CommitSHA:    res.CommitSHA,
		PatchedFiles: paths,
	})
	return err
}

// prBranch is a stable branch name for the fix.
//
// Keyed on the FILE, which is one scan of one build: every finding on that
// scan lands on one branch and one pull request, so re-running the same scan
// updates them rather than opening another. Keying per analysis instead is how
// a file with a dozen findings becomes a dozen pull requests.
//
// The hash fallback covers manual --finding runs, which have no file id and so
// no natural identity beyond the path being patched.
func prBranch(fileID int, path string) string {
	if fileID > 0 {
		return fmt.Sprintf("appknox-autofix/analysis-%d", fileID)
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

	// Above everything else: a reviewer who misses this reads an incomplete
	// branch as a complete one, and treats findings never attempted as fixed.
	if inputs.RunNote != "" {
		fmt.Fprintf(&b, "> **Incomplete run.** %s\n\n", inputs.RunNote)
	}

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
