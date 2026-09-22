package helper

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/appknox/appknox-go/appknox"
)

// stubDeps builds autofixDeps whose analysisIDs and fetch are canned.
func stubDeps(ids []int, rem map[int]string) autofixDeps {
	return autofixDeps{
		analysisIDs: func(_ context.Context, _, _ int) ([]int, error) {
			return ids, nil
		},
		fetch: func(_ context.Context, _, analysisID int) (FindingInputs, error) {
			return FindingInputs{
				Finding:     fmt.Sprintf("v%d", analysisID),
				Remediation: rem[analysisID],
			}, nil
		},
	}
}

func TestResolveTargets_KeepsOnlyAnalysesKnoxIQCanFix(t *testing.T) {
	d := stubDeps([]int{1, 2, 3}, map[int]string{1: "fix a", 3: "fix c"})

	got, err := resolveTargets(context.Background(), AutofixOptions{FileID: 24}, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 fixable targets, got %d", len(got))
	}
	if got[0].AnalysisID != 1 || got[1].AnalysisID != 3 {
		t.Fatalf("want analyses 1 and 3, got %d and %d", got[0].AnalysisID, got[1].AnalysisID)
	}
}

func TestResolveTargets_ClassHintsAreNotRequired(t *testing.T) {
	// The whole point of the port: a manifest finding names no Lcom/...; class
	// but is still attempted, because KnoxIQ said it is fixable.
	d := stubDeps([]int{7}, map[int]string{7: "set android:allowBackup=false"})

	got, err := resolveTargets(context.Background(), AutofixOptions{FileID: 24}, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("a finding with no class hint must still be attempted, got %d", len(got))
	}
	if len(got[0].Inputs.ClassHints) != 0 {
		t.Fatal("this fixture deliberately has no class hints")
	}
}

func TestResolveTargets_NothingFixableIsNotAFailure(t *testing.T) {
	d := stubDeps([]int{1, 2}, map[int]string{})

	_, err := resolveTargets(context.Background(), AutofixOptions{FileID: 24}, d)
	if !errors.Is(err, ErrNothingFixable) {
		t.Fatalf("a clean file must report ErrNothingFixable, got %v", err)
	}
}

func TestResolveTargets_OneBadAnalysisDoesNotAbandonTheRest(t *testing.T) {
	d := autofixDeps{
		analysisIDs: func(_ context.Context, _, _ int) ([]int, error) { return []int{1, 2}, nil },
		fetch: func(_ context.Context, _, analysisID int) (FindingInputs, error) {
			if analysisID == 1 {
				return FindingInputs{}, errors.New("knoxiq exploded")
			}
			return FindingInputs{Finding: "v2", Remediation: "fix"}, nil
		},
	}

	got, err := resolveTargets(context.Background(), AutofixOptions{FileID: 24}, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].AnalysisID != 2 {
		t.Fatalf("the surviving analysis must still be attempted, got %v", got)
	}
}

func TestResolveTargets_SingleAnalysisMode(t *testing.T) {
	d := stubDeps(nil, map[int]string{9: "fix"})

	got, err := resolveTargets(context.Background(),
		AutofixOptions{FileID: 24, AnalysisID: 9}, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].AnalysisID != 9 {
		t.Fatalf("want exactly analysis 9, got %v", got)
	}
}

func TestResolveTargets_ManualFindingNeedsNoLookup(t *testing.T) {
	d := autofixDeps{
		analysisIDs: func(context.Context, int, int) ([]int, error) {
			t.Fatal("manual --finding must not hit Appknox")
			return nil, nil
		},
	}

	got, err := resolveTargets(context.Background(),
		AutofixOptions{Finding: "Weak PRNG", ClassHint: "Lcom/x/A;"}, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Inputs.Finding != "Weak PRNG" {
		t.Fatalf("want the manual finding passed straight through, got %v", got)
	}
}

// TestLocatableAnalysisIDs_ExcludesPassedAnalyses is the regression test for
// the RiskThreshold default (runAutofix now sends 1, not 0, when the caller
// left it unset): a Passed analysis (ComputedRisk 0) must be excluded under
// that default, while anything at or above it is kept.
func TestLocatableAnalysisIDs_ExcludesPassedAnalyses(t *testing.T) {
	analyses := []*appknox.Analysis{
		{ID: 101, ComputedRisk: 0}, // Passed -- excluded under the default (threshold 1)
		{ID: 102, ComputedRisk: 1}, // Low -- included
		{ID: 103, ComputedRisk: 3}, // Critical -- included
	}
	analysesFor := func(context.Context, int) ([]*appknox.Analysis, error) { return analyses, nil }

	ids, err := locatableAnalysisIDs(context.Background(), analysesFor, 24, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != 102 || ids[1] != 103 {
		t.Fatalf("want [102 103] (ComputedRisk 0 excluded), got %v", ids)
	}
}

func TestResolveTargets_RequiresFileIDOrFinding(t *testing.T) {
	_, err := resolveTargets(context.Background(), AutofixOptions{}, autofixDeps{})
	if err == nil {
		t.Fatal("want an error when neither --file-id nor --finding is given")
	}
}

func TestIsGatewayBudgetExhausted(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{errors.New("429 session call budget exhausted"), true},
		{errors.New("403 invalid credential"), true},
		{errors.New("some real bug in the fixer"), false},
		{nil, false},
	} {
		if got := isGatewayBudgetExhausted(tc.err); got != tc.want {
			t.Errorf("isGatewayBudgetExhausted(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
