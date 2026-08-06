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

// deliverBranch pushes the patched file to a new branch on GitHub (no PR opened)
// and returns a compare URL. Used when --push-branch is set.
func deliverBranch(ctx context.Context, opts AutofixOptions, path, content string, inputs FindingInputs) (string, error) {
	owner, name, err := splitRepo(opts.Repo)
	if err != nil {
		return "", errors.New("--push-branch needs --repo owner/name")
	}
	token := firstNonEmpty(opts.GithubToken, os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return "", errors.New("--push-branch needs a GitHub token (--github-token or GITHUB_TOKEN)")
	}
	return ghpr.PushBranch(ctx,
		ghpr.Config{Owner: owner, Repo: name, BaseRef: opts.Ref, Token: token},
		ghpr.Change{
			Branch: prBranch(opts.AnalysisID, path), Path: path,
			Content: content, Message: commitMessage(inputs, path),
		})
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
