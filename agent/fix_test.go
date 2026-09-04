package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestBuildDiff(t *testing.T) {
	d := buildDiff([]editRecord{{Path: "A.java", Old: "old", New: "new"}})
	require.Contains(t, d, "--- A.java")
	require.Contains(t, d, "- old")
	require.Contains(t, d, "+ new")
}
