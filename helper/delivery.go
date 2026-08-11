package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/appknox/appknox-go/ghpr"
)

// deliverBranch pushes all patched files to one new branch on GitHub (no PR
// opened) and returns a compare URL. Used when --push-branch is set.
func deliverBranch(ctx context.Context, opts AutofixOptions, patches []filePatch, inputs FindingInputs) (string, error) {
	owner, name, err := splitRepo(opts.Repo)
	if err != nil {
		return "", errors.New("--push-branch needs --repo owner/name")
	}
	token := firstNonEmpty(opts.GithubToken, os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return "", errors.New("--push-branch needs a GitHub token (--github-token or GITHUB_TOKEN)")
	}
	files := make([]ghpr.FileChange, len(patches))
	for i, p := range patches {
		files[i] = ghpr.FileChange{Path: p.Path, Content: p.Content, Message: commitMessage(inputs, p.Path)}
	}
	return ghpr.PushFiles(ctx,
		ghpr.Config{Owner: owner, Repo: name, BaseRef: opts.Ref, Token: token},
		prBranch(opts.AnalysisID, patches[0].Path), files)
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
