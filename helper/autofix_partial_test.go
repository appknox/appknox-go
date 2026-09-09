package helper

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/stretchr/testify/require"
)

// A spent gateway budget must TRUNCATE the run, not void it.
//
// One autofix run is one gateway session, so a large scan can exhaust the
// per-session call budget partway through. Aborting would discard every patch
// already produced -- and already paid for in model calls -- leaving the
// developer nothing. Worse, findings never attempted would be
// indistinguishable from findings checked and found clean.

// budgetErr is what the gateway returns once the session budget is spent. The
// SDK surfaces the body as an opaque error, which is why detection is textual.
func budgetErr() error {
	return errors.New(`failed to get next message: POST "https://gw/anthropic/v1/messages": ` +
		`429 Too Many Requests {"detail":"session call budget exhausted"}`)
}

func TestRunAutofix_budgetExhausted_deliversWhatWasFixed(t *testing.T) {
	root, a, b := multiFileRepo(t)

	var calls int
	d := deps("", fixResult{Changed: true, PatchedContent: "fixed with SecureRandom\n"}, FindingInputs{})
	d.analysisIDs = func(context.Context, int, int) ([]int, error) { return []int{101, 102, 103}, nil }
	d.fetch = func(_ context.Context, _, id int) (FindingInputs, error) {
		return withCriteria("finding", map[int]string{101: "com/x/A", 102: "com/x/B", 103: "com/x/C"}[id]), nil
	}
	d.locate = func(_ context.Context, _ agent.Config, req agent.Request) (string, error) {
		return map[string]string{"com/x/A": a, "com/x/B": b}[req.ClassHint], nil
	}
	// First analysis succeeds; the next exhausts the budget.
	d.agentFix = func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
		calls++
		if calls > 1 {
			return agent.FixResult{}, budgetErr()
		}
		return agent.FixResult{Changed: true, PatchedContent: "fixed with SecureRandom\n"}, nil
	}

	opts := appknoxOpts(root)
	opts.AnalysisID = 0 // whole file

	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err, "a spent budget must not fail the run")
	require.NotEmpty(t, out.Patches, "the fix produced before the budget ran out must survive")
	require.NotEmpty(t, out.Truncated, "a truncated run must say so")
	require.Contains(t, out.Truncated, "3", "the note should say how many analyses there were")
}

// The counterpart: an ordinary fix failure must still abort. If this ever
// passes as a truncation, a real bug would ship as a "partial" branch.
func TestRunAutofix_ordinaryFailure_stillAborts(t *testing.T) {
	root, a, _ := multiFileRepo(t)
	d := deps(a, fixResult{}, withCriteria("finding", "com/x/A"))
	d.analysisIDs = func(context.Context, int, int) ([]int, error) { return []int{101}, nil }
	d.agentFix = func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
		return agent.FixResult{}, errors.New("the fixer exploded")
	}

	opts := appknoxOpts(root)
	opts.AnalysisID = 0

	_, err := runAutofix(context.Background(), opts, d)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exploded")
}

// Detection is textual, so its edges are worth pinning: too broad and real fix
// failures get reported as truncated runs.
func TestIsGatewayBudgetExhausted(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"429 budget", budgetErr(), true},
		{"403 expired session", errors.New(`403 Forbidden {"detail":"invalid credential"}`), true},
		{"mixed case", errors.New("Session Call Budget Exhausted"), true},
		{"ordinary fix failure", errors.New("the fixer produced no edit"), false},
		{"unrelated 429", errors.New("429 upstream rate limit"), false},
		{"bad appknox token", errors.New(`401 {"detail":"Invalid token."}`), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, isGatewayBudgetExhausted(tc.err))
		})
	}
}

// The note has to reach the reviewer, not just the CI log: a partial branch
// that reads as complete is worse than no branch at all.
func TestPRBody_flagsATruncatedRun(t *testing.T) {
	patches := []filePatch{{Path: "app/src/main/java/A.java"}}

	body := prBody(FindingInputs{Finding: "3 findings"}, patches)
	require.NotContains(t, body, "Incomplete run", "a complete run must not be labelled partial")

	body = prBody(FindingInputs{
		Finding: "3 findings",
		RunNote: "the gateway session budget ran out after 1 of 3 analyses",
	}, patches)
	require.Contains(t, body, "Incomplete run")
	require.Contains(t, body, "1 of 3")
	require.Less(t, strings.Index(body, "Incomplete run"), strings.Index(body, "Files changed"),
		"the warning must appear before the file list, where it cannot be skimmed past")
}
