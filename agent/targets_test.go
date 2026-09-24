package agent

import (
	"context"
	"errors"
	"testing"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/stretchr/testify/require"
)

func TestTargetsUserPrompt_CarriesFullKnoxIQText(t *testing.T) {
	p := targetsUserPrompt(TargetRequest{
		VulnerabilityID: 40,
		Finding:         "Unprotected Exported Service",
		Title:           "Exported service overscured.ovaa.InsecureLoggerService",
		Description:     "The service is exported without a permission.",
		Remediation:     "Set android:exported=\"false\".\n\nSteps:\n- Edit AndroidManifest.xml",
	})
	for _, want := range []string{
		"Vulnerability 40: Unprotected Exported Service",
		"overscured.ovaa.InsecureLoggerService",
		"exported without a permission",
		"Set android:exported=\"false\"",
		"- Edit AndroidManifest.xml",
	} {
		require.Contains(t, p, want)
	}
	require.NotContains(t, p, "Class/symbol hint", "no hint line when there is no hint")
}

func TestTargetsUserPrompt_ManualHintPath(t *testing.T) {
	p := targetsUserPrompt(TargetRequest{Finding: "Weak PRNG", ClassHint: "Lcom/x/A;"})
	require.Contains(t, p, "Finding: Weak PRNG")
	require.Contains(t, p, "Class/symbol hint: Lcom/x/A;")
	require.NotContains(t, p, "KnoxIQ remediation", "empty sections are omitted")
}

func TestTargetsSystemPrompt_DemandsJSONAndNamesCompiledForms(t *testing.T) {
	for _, want := range []string{
		`"targets"`, `"not_found"`, "Foo$3", "overscured", "res/layout", "AndroidManifest.xml",
		"okhttp3", "grep or glob", "needs_new_file",
	} {
		require.Contains(t, targetsSystemPrompt, want)
	}
}

func TestParseTargetReply_Valid(t *testing.T) {
	r, err := parseTargetReply(`{"targets":[{"path":"app/src/main/AndroidManifest.xml","why":"exported=false"}],"not_found":[]}`)
	require.NoError(t, err)
	require.Equal(t, []Target{{Path: "app/src/main/AndroidManifest.xml", Why: "exported=false"}}, r.Targets)
	require.Empty(t, r.NotFound)
}

func TestParseTargetReply_FencedWithProse(t *testing.T) {
	text := "I checked the manifest.\n```json\n" +
		`{"targets":[{"path":"a/B.java","why":"x"}],"not_found":["okhttp3.Response: library"]}` +
		"\n```\nDone."
	r, err := parseTargetReply(text)
	require.NoError(t, err)
	require.Equal(t, []Target{{Path: "a/B.java", Why: "x"}}, r.Targets)
	require.Equal(t, []string{"okhttp3.Response: library"}, r.NotFound)
}

func TestParseTargetReply_BraceInsideWhy(t *testing.T) {
	r, err := parseTargetReply(`{"targets":[{"path":"a/B.java","why":"wrap body in if (x) { ... }"}]}`)
	require.NoError(t, err)
	require.Equal(t, "wrap body in if (x) { ... }", r.Targets[0].Why)
}

// TestParseTargetReply_ValidThenProseWithBrace is F6: the old parser anchored
// on the LAST '}' in the whole reply, so trailing prose that happens to
// contain a '}' pushed body past the real JSON value and made a perfectly
// valid reply unparseable.
func TestParseTargetReply_ValidThenProseWithBrace(t *testing.T) {
	text := `{"targets":[{"path":"a/B.java","why":"x"}],"not_found":[]}` +
		"\n\nLet me know if you'd like the closing brace explained further }."
	r, err := parseTargetReply(text)
	require.NoError(t, err)
	require.Equal(t, []Target{{Path: "a/B.java", Why: "x"}}, r.Targets)
}

func TestParseTargetReply_Malformed(t *testing.T) {
	_, err := parseTargetReply(`{"targets": [{"path": "a"`)
	require.ErrorIs(t, err, ErrUnparseableReply)
	_, err = parseTargetReply("app/src/main/AndroidManifest.xml")
	require.ErrorIs(t, err, ErrUnparseableReply, "a bare path is no longer an answer")
}

func TestParseTargetReply_MissingTargetsField(t *testing.T) {
	_, err := parseTargetReply(`{"not_found":["x"]}`)
	require.ErrorIs(t, err, ErrUnparseableReply)
}

func TestParseTargetReply_EmptyTargetsWithNotFound(t *testing.T) {
	r, err := parseTargetReply(`{"targets":[],"not_found":["android.util.Log: framework class"]}`)
	require.NoError(t, err)
	require.Empty(t, r.Targets)
	require.Equal(t, []string{"android.util.Log: framework class"}, r.NotFound)
}

// TestParseTargetReply_NeedsNewFile is stage A: a remediation that needs a
// file that does not exist yet is carried through in its own structured
// field, never inferred from not_found free text.
func TestParseTargetReply_NeedsNewFile(t *testing.T) {
	r, err := parseTargetReply(`{"targets":[{"path":"a/B.java","why":"x"}],` +
		`"needs_new_file":["SecureBaseActivity: base class the activities must extend"]}`)
	require.NoError(t, err)
	require.Equal(t, []string{"SecureBaseActivity: base class the activities must extend"}, r.NeedsNewFile)
}

// TestParseTargetReply_NoNeedsNewFileFieldLeavesItNil is stage A: a reply
// with no needs_new_file field still parses, and the field is nil rather
// than an empty slice, so callers can test len() the same way either way.
func TestParseTargetReply_NoNeedsNewFileFieldLeavesItNil(t *testing.T) {
	r, err := parseTargetReply(`{"targets":[{"path":"a/B.java","why":"x"}]}`)
	require.NoError(t, err)
	require.Nil(t, r.NeedsNewFile)
}

func TestLocateTargetsWith_ParsesRunnerText(t *testing.T) {
	run := func(context.Context, Config, TargetRequest) (string, error) {
		return `{"targets":[{"path":"a/B.java","why":"w"}]}`, nil
	}
	r, err := locateTargetsWith(context.Background(), Config{}, TargetRequest{}, run)
	require.NoError(t, err)
	require.Equal(t, "a/B.java", r.Targets[0].Path)
}

func TestLocateTargetsWith_PropagatesRunnerError(t *testing.T) {
	run := func(context.Context, Config, TargetRequest) (string, error) {
		return "", errors.New("404 page not found")
	}
	_, err := locateTargetsWith(context.Background(), Config{}, TargetRequest{}, run)
	require.EqualError(t, err, "404 page not found")
}

func TestTargetsParams_AppliesDefaults(t *testing.T) {
	p := targetsParams(Config{}, TargetRequest{Finding: "y"})
	require.Equal(t, sdk.ModelClaudeSonnet5, p.Model)
	require.Equal(t, int64(defaultTargetsMaxTokens), p.MaxTokens)
	require.Equal(t, defaultMaxIterations, p.MaxIterations)
	require.Equal(t, targetsSystemPrompt, p.System[0].Text)
}

func TestTargetsParams_HonoursOverrides(t *testing.T) {
	p := targetsParams(Config{Model: "claude-x", MaxTokens: 42, MaxIterations: 3}, TargetRequest{})
	require.Equal(t, sdk.Model("claude-x"), p.Model)
	require.Equal(t, int64(42), p.MaxTokens)
	require.Equal(t, 3, p.MaxIterations)
}

func TestSdkLocateTargets_RequiresConfig(t *testing.T) {
	_, err := sdkLocateTargets(context.Background(), Config{}, TargetRequest{RepoRoot: t.TempDir()})
	require.Error(t, err)
}
