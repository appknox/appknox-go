package helper

import (
	"context"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/stretchr/testify/require"
)

// The model flags exist on autofix-v3 but were dropped by the KnoxIQ targeting
// port, so every run since has been pinned to the SDK default (Sonnet) with no
// way to select another. That matters beyond cost: the recorded corpus results
// are split by model, so a run whose model cannot be chosen cannot be compared
// against them.
//
// The asymmetry below is the point, and is v3's: locate answers the cheaper
// question ("which file?") and may run on a smaller model, while the fix turn
// writes the patch that actually ships and therefore honours --model ONLY.
// Letting --locate-model leak into the fix turn would silently downgrade the
// patch, which is exactly what these tests exist to prevent.

// captureModels runs one target through a session and reports the model each
// turn was configured with.
func captureModels(t *testing.T, opts AutofixOptions) (locateModel, fixModel string) {
	t.Helper()
	root, rel := repoWithFile(t, "orig\n")
	opts.FixMode = "agent"
	opts.FileID = 1
	// Dry-run so the session stops before delivery: both turns still run (the
	// dry-run return sits below the fix loop), and the test needs neither a
	// GitHub push nor a deliver stub to observe the models.
	opts.DryRun = true
	s := fixSession{
		opts: opts,
		root: root,
		// These cases produce a real patch, so run() reaches work.apply; an
		// unset work is a nil deref there.
		work: newWorkingTree(root),
		d: autofixDeps{
			locateTargets: func(_ context.Context, cfg agent.Config, _ agent.TargetRequest) (agent.TargetReply, error) {
				locateModel = cfg.Model
				return agent.TargetReply{Targets: []agent.Target{{Path: rel}}}, nil
			},
			agentFix: func(_ context.Context, cfg agent.Config, _ agent.FixRequest) (agent.FixResult, error) {
				fixModel = cfg.Model
				return agent.FixResult{Changed: true, PatchedContent: "fixed\n", Diff: "-old\n+new"}, nil
			},
		},
		targets: []analysisTarget{
			{AnalysisID: 1, Inputs: FindingInputs{
				Finding: "insecure randomness", Remediation: "use SecureRandom",
			}},
		},
	}
	_, err := s.run(context.Background())
	require.NoError(t, err)
	return locateModel, fixModel
}

func TestModel_UnsetLeavesBothTurnsOnTheSDKDefault(t *testing.T) {
	locateModel, fixModel := captureModels(t, AutofixOptions{})
	require.Empty(t, locateModel, "an unset --model must not invent a model; the agent layer picks the default")
	require.Empty(t, fixModel, "an unset --model must not invent a model for the fix turn either")
}

func TestModel_AppliesToBothTurns(t *testing.T) {
	locateModel, fixModel := captureModels(t, AutofixOptions{Model: "claude-haiku-4-5-20251001"})
	require.Equal(t, "claude-haiku-4-5-20251001", locateModel)
	require.Equal(t, "claude-haiku-4-5-20251001", fixModel)
}

// The whole reason --locate-model exists: run locate cheap, keep the patch turn
// on the better model. If this test fails because fixModel picked up the locate
// model, the flag is actively harmful -- it would quietly downgrade the shipped
// patch while appearing to only affect locating.
func TestModel_LocateModelOverridesLocateTurnOnly(t *testing.T) {
	locateModel, fixModel := captureModels(t, AutofixOptions{
		Model:       "claude-sonnet-5",
		LocateModel: "claude-haiku-4-5-20251001",
	})
	require.Equal(t, "claude-haiku-4-5-20251001", locateModel, "--locate-model must win for the locate turn")
	require.Equal(t, "claude-sonnet-5", fixModel, "--locate-model must NEVER reach the turn that writes the patch")
}

// --locate-model alone, with no --model, still steers locate; the fix turn
// falls through to the SDK default rather than borrowing the locate model.
func TestModel_LocateModelAloneDoesNotSetTheFixTurn(t *testing.T) {
	locateModel, fixModel := captureModels(t, AutofixOptions{LocateModel: "claude-haiku-4-5-20251001"})
	require.Equal(t, "claude-haiku-4-5-20251001", locateModel)
	require.Empty(t, fixModel, "the fix turn must fall back to the default, not to --locate-model")
}
