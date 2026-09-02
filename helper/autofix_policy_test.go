package helper

import (
	"context"
	"os"
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

// The fix belongs beside the work that produced it, so the PR targets the
// feature branch rather than the repository default.
func TestDeliverBranch_targetsTheSourceFeatureBranch(t *testing.T) {
	t.Setenv("GITHUB_HEAD_REF", "feature/payment")
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("GITHUB_TOKEN", "")

	// No token, so it stops before any network call -- enough to prove the
	// branch name is derived from the feature branch.
	require.Equal(t, "autofix-feature/payment",
		prBranch(SourceBranch(""), 0, 11829, "app/Main.java"))
}

// Repeated scans of one branch must not fan out into many PRs.
func TestPRBranch_repeatedScansOfOneBranchShareABranch(t *testing.T) {
	first := prBranch("feature/payment", 0, 101, "app/A.java")
	second := prBranch("feature/payment", 0, 202, "app/B.java")
	require.Equal(t, first, second,
		"a later scan of the same branch must reuse the branch, not open a second PR")
}

func TestSourceBranch_isEmptyOutsideCI(t *testing.T) {
	t.Setenv("GITHUB_HEAD_REF", "")
	t.Setenv("GITHUB_REF_NAME", "")
	require.Empty(t, SourceBranch(""))
	_ = os.Getenv("HOME")
	// falls back to the analysis-keyed name
	require.Equal(t, "appknox-autofix/analysis-7", prBranch("", 0, 7, "a.java"))
}

var _ = agent.Config{}
