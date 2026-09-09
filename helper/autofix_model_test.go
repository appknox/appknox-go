package helper

import (
	"context"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/stretchr/testify/require"
)

// Which model runs WHICH turn is a security-relevant choice, not a cost knob.
//
// Locating answers "which file holds this class?" from grep and glob output.
// Fixing writes the patch that ships. Running a cheaper model for locate is
// where the saving is; letting that choice leak into the fix turn would quietly
// downgrade the model writing security patches, and nothing in the output would
// show it.

// captureModels runs one analysis and reports the model each turn received.
func captureModels(t *testing.T, opts AutofixOptions, path string) (locate, fix string) {
	t.Helper()
	d := deps(path, fixResult{Changed: true, PatchedContent: "fixed with SecureRandom\n"},
		withCriteria("Weak PRNG", "com/x/A"))
	d.locate = func(_ context.Context, cfg agent.Config, _ agent.Request) (string, error) {
		locate = cfg.Model
		return path, nil
	}
	d.agentFix = func(_ context.Context, cfg agent.Config, _ agent.FixRequest) (agent.FixResult, error) {
		fix = cfg.Model
		return agent.FixResult{Changed: true, PatchedContent: "fixed with SecureRandom\n"}, nil
	}
	_, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	return locate, fix
}

func TestModelSelection(t *testing.T) {
	const haiku = "claude-haiku-4-5-20251001"
	const sonnet = "claude-sonnet-5"

	t.Run("unset leaves both to the SDK default", func(t *testing.T) {
		root, a, _ := multiFileRepo(t)
		locate, fix := captureModels(t, appknoxOpts(root), a)
		require.Empty(t, locate, "an unset model must not be invented here")
		require.Empty(t, fix)
	})

	t.Run("model applies to both turns", func(t *testing.T) {
		root, a, _ := multiFileRepo(t)
		opts := appknoxOpts(root)
		opts.Model = sonnet
		locate, fix := captureModels(t, opts, a)
		require.Equal(t, sonnet, locate)
		require.Equal(t, sonnet, fix)
	})

	t.Run("locateModel narrows to the locate turn only", func(t *testing.T) {
		root, a, _ := multiFileRepo(t)
		opts := appknoxOpts(root)
		opts.Model = sonnet
		opts.LocateModel = haiku
		locate, fix := captureModels(t, opts, a)
		require.Equal(t, haiku, locate, "locate should take the cheaper model")
		require.Equal(t, sonnet, fix,
			"the fix turn writes the patch and must NOT inherit the locate model")
	})

	t.Run("locateModel alone does not reach the fix turn", func(t *testing.T) {
		root, a, _ := multiFileRepo(t)
		opts := appknoxOpts(root)
		opts.LocateModel = haiku
		locate, fix := captureModels(t, opts, a)
		require.Equal(t, haiku, locate)
		require.Empty(t, fix, "with no --model the fix turn keeps the default")
	})
}
