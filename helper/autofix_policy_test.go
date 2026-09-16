package helper

import (
	"context"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/stretchr/testify/require"
)

// One severity policy, not two: autofix reuses the cicheck threshold rather
// than asking the customer to configure "what matters" a second time.
func TestRiskThreshold_isPassedThroughToTargetSelection(t *testing.T) {
	var gotThreshold int
	d := defaultDeps()
	d.analysisIDs = func(_ context.Context, _ int, threshold int) ([]int, error) {
		gotThreshold = threshold
		return []int{1}, nil
	}
	d.fetch = func(context.Context, int, int) (FindingInputs, error) {
		return withCriteria("f", "com/x/A"), nil
	}
	_, err := resolveTargets(context.Background(),
		AutofixOptions{FileID: 9, RiskThreshold: 3}, d)
	require.NoError(t, err)
	require.Equal(t, 3, gotThreshold, "the configured threshold must reach the filter")
}

// The branch is keyed on the FILE -- one scan of one build -- so every finding
// on that scan lands on one branch and one pull request.
func TestPRBranch_isKeyedOnTheFile(t *testing.T) {
	require.Equal(t, "appknox-autofix/analysis-11829",
		prBranch(11829, "app/Main.java"))
}

// A file with many findings must not fan out into many pull requests. Two
// different paths patched under the same scan share one branch.
func TestPRBranch_everyFindingOnAScanSharesABranch(t *testing.T) {
	first := prBranch(101, "app/A.java")
	second := prBranch(101, "app/B.java")
	require.Equal(t, first, second,
		"findings from one scan must reuse the branch, not open a second PR")
}

// Re-running the same scan updates the existing branch rather than opening
// another, because the name is derived and not generated.
func TestPRBranch_isStableAcrossRuns(t *testing.T) {
	require.Equal(t, prBranch(7, "a.java"), prBranch(7, "a.java"))
}

// Manual --finding runs have no file id, so the path is the only identity
// available; it must still be deterministic.
func TestPRBranch_fallsBackToThePathHashWithoutAFileID(t *testing.T) {
	got := prBranch(0, "app/Main.java")
	require.Equal(t, got, prBranch(0, "app/Main.java"))
	require.Contains(t, got, "appknox-autofix/fix-")
	require.NotEqual(t, got, prBranch(0, "app/Other.java"))
}

var _ = agent.Config{}
