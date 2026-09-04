package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	anthropic "github.com/anthropics/anthropic-sdk-go"
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

	run := func(_ context.Context, _ Config, req FixRequest, edits *[]editRecord, _ *string) error {
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
	run := func(context.Context, Config, FixRequest, *[]editRecord, *string) error { return nil }
	res, err := fixWith(context.Background(), Config{}, FixRequest{RepoRoot: root, Path: rel}, run)
	require.NoError(t, err)
	require.False(t, res.Changed)
	require.Equal(t, "unchanged\n", res.PatchedContent)
}

func TestFixWith_PropagatesErrorAndReverts(t *testing.T) {
	root, rel := fixRepo(t, "orig\n")
	run := func(_ context.Context, _ Config, req FixRequest, _ *[]editRecord, _ *string) error {
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

func TestBuildDiff(t *testing.T) {
	d := buildDiff([]editRecord{{Path: "A.java", Old: "old", New: "new"}})
	require.Contains(t, d, "--- A.java")
	require.Contains(t, d, "- old")
	require.Contains(t, d, "+ new")
}

// A fix turn writes code into the edit tool call; a locate turn writes a path.
// Sharing one 1024-token budget silently truncated any fix bigger than a
// one-line swap, so no edit completed and the run looked like an abstention.
func TestFixTurnGetsABiggerTokenBudgetThanLocate(t *testing.T) {
	fix := runnerParamsWithBudget(Config{}, "sys", "user", defaultFixMaxTokens)
	locate := runnerParams(Config{}, "sys", "user")

	require.Greater(t, fix.MaxTokens, locate.MaxTokens)
	require.EqualValues(t, defaultFixMaxTokens, fix.MaxTokens)
}

func TestRunnerParams_ExplicitMaxTokensStillWins(t *testing.T) {
	p := runnerParamsWithBudget(Config{MaxTokens: 999}, "sys", "user", defaultFixMaxTokens)
	require.EqualValues(t, 999, p.MaxTokens)
}

// A truncated or refused turn ends with no text. Reporting that as silence made
// it read as "the model chose not to edit", which is the opposite diagnosis and
// sends you to the prompt instead of the budget.
func TestDeclineReason_NamesTruncationRatherThanLookingLikeAbstention(t *testing.T) {
	msg := &anthropic.BetaMessage{StopReason: anthropic.BetaStopReasonMaxTokens}
	require.Contains(t, declineReason(msg), "output-token limit")

	require.Contains(t, declineReason(nil), "no final message")
}

// When the model does explain itself, its own words win over any inference.
func TestDeclineReason_PrefersTheModelsOwnWords(t *testing.T) {
	msg := &anthropic.BetaMessage{
		StopReason: anthropic.BetaStopReasonMaxTokens,
		Content: []anthropic.BetaContentBlockUnion{
			{Type: "text", Text: "needs Android Keystore, out of scope here"},
		},
	}
	require.Equal(t, "needs Android Keystore, out of scope here", declineReason(msg))
}
