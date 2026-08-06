package helper

import (
	"context"
	"errors"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/stretchr/testify/require"
)

func TestSplitRepo(t *testing.T) {
	o, n, err := splitRepo("appknox/mfva")
	require.NoError(t, err)
	require.Equal(t, "appknox", o)
	require.Equal(t, "mfva", n)

	for _, bad := range []string{"", "noslash", "/name", "owner/"} {
		_, _, err := splitRepo(bad)
		require.Error(t, err, "expected error for %q", bad)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	require.Equal(t, "a", firstNonEmpty("a", "b"))
	require.Equal(t, "b", firstNonEmpty("", "b"))
	require.Equal(t, "", firstNonEmpty("", ""))
}

func TestResolveRepoRoot_LocalPath(t *testing.T) {
	dir := t.TempDir()
	root, cleanup, err := resolveRepoRoot(context.Background(), AutofixOptions{RepoPath: dir})
	require.NoError(t, err)
	require.Equal(t, dir, root)
	require.NotNil(t, cleanup)
	cleanup() // no-op for a local path — must not remove the checkout
	require.DirExists(t, dir)
}

func TestResolveRepoRoot_RequiresRepoOrPath(t *testing.T) {
	_, _, err := resolveRepoRoot(context.Background(), AutofixOptions{})
	require.Error(t, err)
}

func TestRunAutofix_RequiresFinding(t *testing.T) {
	_, err := runAutofix(context.Background(), AutofixOptions{RepoPath: t.TempDir()}, nil)
	require.Error(t, err)
}

func TestRunAutofix_RequiresToken(t *testing.T) {
	t.Setenv("APPKNOX_AUTOFIX_FIX_TOKEN", "")
	_, err := runAutofix(
		context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "weak PRNG"},
		nil,
	)
	require.Error(t, err)
}

func TestRunAutofix_LocatesViaInjectedFn(t *testing.T) {
	dir := t.TempDir()
	var gotReq agent.Request
	locate := func(_ context.Context, cfg agent.Config, req agent.Request) (string, error) {
		gotReq = req
		require.Equal(t, "http://localhost:8100", cfg.FixURL) // default applied
		require.Equal(t, "tok", cfg.Token)
		return "app/Main.java", nil
	}
	path, err := runAutofix(
		context.Background(),
		AutofixOptions{RepoPath: dir, Finding: "weak PRNG", ClassHint: "Main", FixToken: "tok"},
		locate,
	)
	require.NoError(t, err)
	require.Equal(t, "app/Main.java", path)
	require.Equal(t, dir, gotReq.RepoRoot)
	require.Equal(t, "weak PRNG", gotReq.Finding)
}

func TestRunAutofix_PropagatesLocateError(t *testing.T) {
	locate := func(context.Context, agent.Config, agent.Request) (string, error) {
		return "", errors.New("boom")
	}
	_, err := runAutofix(
		context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x", FixToken: "tok"},
		locate,
	)
	require.Error(t, err)
}
