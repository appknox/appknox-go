package helper

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrBranch(t *testing.T) {
	require.Equal(t, "appknox-autofix/analysis-42", prBranch(42, "a.java"))
	require.Contains(t, prBranch(0, "app/Main.java"), "appknox-autofix/fix-") // no id → hashed
}

func TestCommitMessage(t *testing.T) {
	msg := commitMessage(FindingInputs{Finding: "Weak PRNG"}, "app/src/Main.java")
	require.Contains(t, msg, "Weak PRNG")
	require.Contains(t, msg, "Main.java") // basename, not the full path
}

func TestDeliverBranch_RequiresRepoAndToken(t *testing.T) {
	patches := []filePatch{{Path: "app/A.java", Content: "c"}}
	_, err := deliverBranch(context.Background(), AutofixOptions{}, patches, FindingInputs{})
	require.Error(t, err) // no --repo

	t.Setenv("GITHUB_TOKEN", "")
	_, err = deliverBranch(context.Background(), AutofixOptions{Repo: "o/r"}, patches, FindingInputs{})
	require.Error(t, err) // repo but no token
}
