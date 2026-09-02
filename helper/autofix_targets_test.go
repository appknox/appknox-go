package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/stretchr/testify/require"
)

// multiFileRepo makes a checkout with two source files.
func multiFileRepo(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	a, b := "app/A.java", "app/B.java"
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	for _, rel := range []string{a, b} {
		require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte("orig\n"), 0o644))
	}
	return root, a, b
}

// withCriteria builds inputs whose criteria the stub patch satisfies.
func withCriteria(finding, hint string) FindingInputs {
	return FindingInputs{
		Finding: finding, ClassHints: []string{hint}, Remediation: "use SecureRandom",
		Criteria: []string{"Confirm SecureRandom is present"},
	}
}

// A whole file is the default unit of work: one run, every finding.
func TestRunAutofix_AllAnalyses_fixesEveryFinding(t *testing.T) {
	root, a, b := multiFileRepo(t)
	d := deps("", fixResult{Changed: true, PatchedContent: "fixed with SecureRandom\n"}, FindingInputs{})
	d.analysisIDs = func(context.Context, int, int) ([]int, error) { return []int{101, 102}, nil }
	d.fetch = func(_ context.Context, _, analysisID int) (FindingInputs, error) {
		if analysisID == 101 {
			return withCriteria("Weak PRNG", "com/x/A"), nil
		}
		return withCriteria("Derived Crypto Keys", "com/x/B"), nil
	}
	d.locate = func(_ context.Context, _ agent.Config, req agent.Request) (string, error) {
		return map[string]string{"com/x/A": a, "com/x/B": b}[req.ClassHint], nil
	}

	opts := appknoxOpts(root)
	opts.AnalysisID = 0 // whole file
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Len(t, out.Analyses, 2, "both analyses should be reported")
	require.Len(t, out.Patches, 2, "both findings should be fixed")
}

// All of it ships together: one branch per scan, not one per finding.
func TestRunAutofix_AllAnalyses_deliversOnce(t *testing.T) {
	root, a, b := multiFileRepo(t)
	var deliveries, delivered = 0, 0
	d := deps("", fixResult{Changed: true, PatchedContent: "fixed with SecureRandom\n"}, FindingInputs{})
	d.analysisIDs = func(context.Context, int, int) ([]int, error) { return []int{101, 102}, nil }
	d.fetch = func(_ context.Context, _, id int) (FindingInputs, error) {
		if id == 101 {
			return withCriteria("A", "com/x/A"), nil
		}
		return withCriteria("B", "com/x/B"), nil
	}
	d.locate = func(_ context.Context, _ agent.Config, req agent.Request) (string, error) {
		return map[string]string{"com/x/A": a, "com/x/B": b}[req.ClassHint], nil
	}
	d.deliver = func(_ context.Context, _ AutofixOptions, patches []filePatch, _ FindingInputs) (string, error) {
		deliveries++
		delivered = len(patches)
		return "https://github.com/o/r/pull/1", nil
	}

	opts := appknoxOpts(root)
	opts.AnalysisID, opts.Repo, opts.PushBranch = 0, "appknox/mfva", true
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Equal(t, 1, deliveries, "one pull request, not one per finding")
	require.Equal(t, 2, delivered, "carrying every verified patch")
	require.Contains(t, out.BranchURL, "pull/1")
}

// A finding that fails its own criteria is held back; the rest still ship.
func TestRunAutofix_AllAnalyses_holdsBackOnlyTheUnverified(t *testing.T) {
	root, a, b := multiFileRepo(t)
	d := deps("", fixResult{Changed: true, PatchedContent: "fixed with SecureRandom\n"}, FindingInputs{})
	d.analysisIDs = func(context.Context, int, int) ([]int, error) { return []int{101, 102}, nil }
	d.fetch = func(_ context.Context, _, id int) (FindingInputs, error) {
		if id == 101 {
			return withCriteria("good", "com/x/A"), nil
		}
		// no criteria: cannot be checked, must not be delivered
		return FindingInputs{Finding: "unchecked", ClassHints: []string{"com/x/B"},
			Remediation: "fix it"}, nil
	}
	d.locate = func(_ context.Context, _ agent.Config, req agent.Request) (string, error) {
		return map[string]string{"com/x/A": a, "com/x/B": b}[req.ClassHint], nil
	}

	opts := appknoxOpts(root)
	opts.AnalysisID = 0
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err, "one unverifiable finding must not fail the whole run")
	require.Len(t, out.Patches, 1, "only the verified fix ships")
	require.Len(t, out.Analyses, 2)

	var skipped int
	for _, r := range out.Analyses {
		if r.Skipped != "" {
			skipped++
			require.Contains(t, r.Skipped, "verification criteria")
		}
	}
	require.Equal(t, 1, skipped, "the unverified one is reported, not silently dropped")
}

// A single bad analysis should not cost the developer the rest of the scan.
func TestResolveTargets_skipsAnalysesThatFailToResolve(t *testing.T) {
	d := defaultDeps()
	d.analysisIDs = func(context.Context, int, int) ([]int, error) { return []int{1, 2}, nil }
	d.fetch = func(_ context.Context, _, id int) (FindingInputs, error) {
		if id == 1 {
			return FindingInputs{}, errors.New("knoxiq blew up")
		}
		return withCriteria("ok", "com/x/B"), nil
	}
	targets, err := resolveTargets(context.Background(), AutofixOptions{FileID: 9}, d)
	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, 2, targets[0].AnalysisID)
}

func TestResolveTargets_errorsWhenNothingIsFixable(t *testing.T) {
	d := defaultDeps()
	d.analysisIDs = func(context.Context, int, int) ([]int, error) { return []int{1}, nil }
	d.fetch = func(context.Context, int, int) (FindingInputs, error) {
		return FindingInputs{Finding: "x"}, nil // no remediation
	}
	_, err := resolveTargets(context.Background(), AutofixOptions{FileID: 9}, d)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nothing fixable")
}

func TestResolveTargets_singleAnalysisStillWorks(t *testing.T) {
	d := defaultDeps()
	d.fetch = func(_ context.Context, f, a int) (FindingInputs, error) {
		require.Equal(t, 118, f)
		require.Equal(t, 11829, a)
		return withCriteria("Weak PRNG", "com/x/C"), nil
	}
	targets, err := resolveTargets(context.Background(),
		AutofixOptions{FileID: 118, AnalysisID: 11829}, d)
	require.NoError(t, err)
	require.Len(t, targets, 1)
}

func TestResolveTargets_manualFindingNeedsNoLookup(t *testing.T) {
	d := defaultDeps()
	d.fetch = func(context.Context, int, int) (FindingInputs, error) {
		t.Fatal("the manual path must not hit Appknox")
		return FindingInputs{}, nil
	}
	targets, err := resolveTargets(context.Background(),
		AutofixOptions{Finding: "weak PRNG", ClassHint: "Main"}, d)
	require.NoError(t, err)
	require.Equal(t, "weak PRNG", targets[0].Inputs.Finding)
}

func TestResolveTargets_requiresSomething(t *testing.T) {
	_, err := resolveTargets(context.Background(), AutofixOptions{}, defaultDeps())
	require.Error(t, err)
}
