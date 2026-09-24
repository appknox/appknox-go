package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/stretchr/testify/require"
)

func fixRepo(t *testing.T, body string) (string, string) {
	t.Helper()
	root := t.TempDir()
	rel := "app/Main.java"
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte(body), 0o644))
	return root, rel
}

func TestFixWith_AppliesThenReverts(t *testing.T) {
	orig := "int r = new Random().nextInt();\n"
	root, rel := fixRepo(t, orig)

	run := func(_ context.Context, _ Config, req FixRequest, edits *[]editRecord) error {
		// simulate the edit tool writing the patched file + recording the edit
		patched := strings.Replace(orig, "new Random()", "new SecureRandom()", 1)
		require.NoError(t, os.WriteFile(filepath.Join(req.RepoRoot, req.Path), []byte(patched), 0o644))
		*edits = append(*edits, editRecord{Path: req.Path, Old: "new Random()", New: "new SecureRandom()"})
		return nil
	}
	res, err := fixWith(context.Background(), Config{}, FixRequest{RepoRoot: root, Path: rel}, run)
	require.NoError(t, err)
	require.True(t, res.Changed)
	require.Contains(t, res.PatchedContent, "SecureRandom")
	require.Contains(t, res.Diff, "SecureRandom")
	// side-effect-free: the on-disk file is restored to the original
	onDisk, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, orig, string(onDisk))
}

func TestFixWith_NoEdit(t *testing.T) {
	root, rel := fixRepo(t, "unchanged\n")
	run := func(context.Context, Config, FixRequest, *[]editRecord) error { return nil }
	res, err := fixWith(context.Background(), Config{}, FixRequest{RepoRoot: root, Path: rel}, run)
	require.NoError(t, err)
	require.False(t, res.Changed)
	require.Equal(t, "unchanged\n", res.PatchedContent)
}

func TestFixWith_PropagatesErrorAndReverts(t *testing.T) {
	root, rel := fixRepo(t, "orig\n")
	run := func(_ context.Context, _ Config, req FixRequest, _ *[]editRecord) error {
		_ = os.WriteFile(filepath.Join(req.RepoRoot, req.Path), []byte("half-written"), 0o644)
		return errors.New("boom")
	}
	_, err := fixWith(context.Background(), Config{}, FixRequest{RepoRoot: root, Path: rel}, run)
	require.Error(t, err)
	onDisk, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(onDisk)) // reverted even on error
}

func TestFixUserPrompt_IncludesFindingAndRemediation(t *testing.T) {
	p := fixUserPrompt(FixRequest{Path: "app/Main.java", Finding: "Weak PRNG", Remediation: "use SecureRandom"})
	require.Contains(t, p, "app/Main.java")
	require.Contains(t, p, "Weak PRNG")
	require.Contains(t, p, "use SecureRandom")
}

func TestBuildFixTools_HasEditPlusReadOnly(t *testing.T) {
	var edits []editRecord
	tools, err := buildFixTools(t.TempDir(), "app/Main.java", &edits)
	require.NoError(t, err)
	require.Len(t, tools, 4) // read_file, grep, glob, edit
}

// A locate turn answers with one path; a fix turn emits an edit tool call whose
// old_string and new_string carry real code. autofix-v2 sized them separately
// (1024 / 16384); the Mycroft-gateway port collapsed runnerParamsWithBudget
// into runnerParams and put BOTH turns on 1024.
//
// Nothing in helper/ or cmd/ sets Config.MaxTokens, so that default is what
// every real run gets. A fix that does not fit truncates mid-tool-use: no edit
// completes, the final message carries no text, and the run reports "no patch"
// -- indistinguishable from the model judging the code already safe. That is
// the shape of aibom-android's 0-of-11 result, where seven findings were
// attempted and not one produced a patch.
func TestFixParams_GetsTheLargerBudget(t *testing.T) {
	p := fixParams(Config{}, FixRequest{Finding: "weak prng", Remediation: "use SecureRandom"})
	require.Equal(t, int64(defaultFixMaxTokens), p.MaxTokens,
		"the fix turn writes code and must not inherit the locate turn's one-path budget")
}

// The two budgets must stay distinct: if they are ever equal again the collapse
// has come back, and this assertion is the only thing that says so.
func TestFixBudget_IsLargerThanLocateBudget(t *testing.T) {
	require.Greater(t, int64(defaultFixMaxTokens), int64(defaultTargetsMaxTokens))
}

// The per-turn numbers are fallbacks, not overrides: an explicit
// Config.MaxTokens still wins.
func TestFixParams_ExplicitMaxTokensStillWins(t *testing.T) {
	p := fixParams(Config{MaxTokens: 77}, FixRequest{})
	require.Equal(t, int64(77), p.MaxTokens)
}

// Truncation is not abstention. When the runner stops on max_tokens having
// written no edit, the caller must be told the budget ran out rather than
// handed a silent "no change" it would report as a clean skip.
func TestDeclineReason_NamesTruncationRatherThanSilence(t *testing.T) {
	require.Contains(t,
		declineReason(&sdk.BetaMessage{StopReason: sdk.BetaStopReasonMaxTokens}),
		"output-token limit")
}

func TestDeclineReason_NamesRefusal(t *testing.T) {
	require.Contains(t,
		declineReason(&sdk.BetaMessage{StopReason: sdk.BetaStopReasonRefusal}),
		"refused")
}

// A model that finished normally and explained itself is a real abstention; its
// own words are the reason and must not be overwritten by a guess.
func TestDeclineReason_PrefersTheModelsOwnWords(t *testing.T) {
	msg := &sdk.BetaMessage{
		StopReason: sdk.BetaStopReasonEndTurn,
		Content:    []sdk.BetaContentBlockUnion{{Type: "text", Text: "this file is already safe"}},
	}
	require.Equal(t, "this file is already safe", declineReason(msg))
}

func TestDeclineReason_NilMessage(t *testing.T) {
	require.NotEmpty(t, declineReason(nil))
}

// M1: a truncated reply commonly leaves a text preamble it started before
// running out of budget (e.g. "I'll start by reading the file..."). Reporting
// that preamble as the model's own considered reason -- the bug before this
// fix -- hides the real, mechanical cause. BetaStopReasonMaxTokens must win
// even when text is present.
func TestDeclineReason_MaxTokensWinsOverATextPreamble(t *testing.T) {
	msg := &sdk.BetaMessage{
		StopReason: sdk.BetaStopReasonMaxTokens,
		Content:    []sdk.BetaContentBlockUnion{{Type: "text", Text: "I'll start by reading the file and then"}},
	}
	got := declineReason(msg)
	require.Contains(t, got, "output-token limit")
	require.NotContains(t, got, "I'll start by reading the file",
		"a mid-thought preamble must never be reported as the model's considered reason")
}

// M1: the printed reason must be bounded, not an unbounded dump of whatever
// the model wrote.
func TestDeclineReason_BoundsLength(t *testing.T) {
	msg := &sdk.BetaMessage{
		StopReason: sdk.BetaStopReasonEndTurn,
		Content:    []sdk.BetaContentBlockUnion{{Type: "text", Text: strings.Repeat("x", 5000)}},
	}
	got := declineReason(msg)
	require.Less(t, len(got), 5000, "an unbounded model reply must be capped, not printed in full")
}

func TestBuildDiff(t *testing.T) {
	d := buildDiff([]editRecord{{Path: "A.java", Old: "old", New: "new"}})
	require.Contains(t, d, "--- A.java")
	require.Contains(t, d, "- old")
	require.Contains(t, d, "+ new")
}
