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

func TestLocateUserPrompt_IncludesHintAndAbstainToken(t *testing.T) {
	p := locateUserPrompt(Request{ClassHint: "com/appknox/mfva/MainActivity", Finding: "weak PRNG"})
	require.Contains(t, p, "com/appknox/mfva/MainActivity")
	require.Contains(t, p, "weak PRNG")
	require.Contains(t, p, "NONE")
}

func TestLocateWith_ReturnsValidatedPath(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app/src/main/java/com/appknox/mfva")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "MainActivity.java"), []byte("x"), 0o644))
	rel := "app/src/main/java/com/appknox/mfva/MainActivity.java"

	run := func(context.Context, Config, Request) (string, error) { return "It is " + rel, nil }
	got, err := locateWith(context.Background(), Config{}, Request{RepoRoot: root}, run)
	require.NoError(t, err)
	require.Equal(t, rel, got)
}

func TestLocateWith_AbstainsWhenModelSaysNone(t *testing.T) {
	run := func(context.Context, Config, Request) (string, error) { return "NONE", nil }
	got, err := locateWith(context.Background(), Config{}, Request{RepoRoot: t.TempDir()}, run)
	require.NoError(t, err)
	require.Equal(t, "", got)
}

func TestLocateWith_PropagatesRunnerError(t *testing.T) {
	run := func(context.Context, Config, Request) (string, error) { return "", errors.New("boom") }
	_, err := locateWith(context.Background(), Config{}, Request{RepoRoot: t.TempDir()}, run)
	require.Error(t, err)
}

func TestLocateParams_AppliesDefaults(t *testing.T) {
	p := locateParams(Config{}, Request{ClassHint: "X", Finding: "y"})
	require.Equal(t, anthropic.ModelClaudeSonnet5, p.Model)
	require.Equal(t, int64(defaultMaxTokens), p.MaxTokens)
	require.Equal(t, defaultMaxIterations, p.MaxIterations)
	require.NotEmpty(t, p.System)
	require.True(t, strings.Contains(p.System[0].Text, "read-only"))
}

func TestLocateParams_HonoursOverrides(t *testing.T) {
	p := locateParams(Config{Model: "claude-x", MaxTokens: 42, MaxIterations: 3}, Request{})
	require.Equal(t, anthropic.Model("claude-x"), p.Model)
	require.Equal(t, int64(42), p.MaxTokens)
	require.Equal(t, 3, p.MaxIterations)
}

func TestSdkLocate_RequiresConfig(t *testing.T) {
	// Missing FixURL/Token must fail before any network call.
	_, err := sdkLocate(context.Background(), Config{}, Request{RepoRoot: t.TempDir()})
	require.Error(t, err)
}
