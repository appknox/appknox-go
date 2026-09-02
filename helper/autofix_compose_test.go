package helper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/stretchr/testify/require"
)

// Two findings in ONE file must compose, not overwrite.
//
// mfva PR #18 shipped with a crypto fix missing: two analyses both patched
// MainActivity.java, each starting from the original content, and the second
// push silently discarded the first.
func TestRunAutofix_TwoFindingsInOneFile_compose(t *testing.T) {
	root := t.TempDir()
	rel := "app/Main.java"
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, rel),
		[]byte("weak();\ninsecure();\n"), 0o644))

	var delivered []filePatch
	d := deps(rel, fixResult{}, FindingInputs{})
	d.analysisIDs = func(context.Context, int, int) ([]int, error) { return []int{1, 2}, nil }
	d.fetch = func(_ context.Context, _, id int) (FindingInputs, error) {
		return withCriteria("finding", "com/x/Main"), nil
	}
	d.locate = func(context.Context, agent.Config, agent.Request) (string, error) { return rel, nil }
	// Each fix edits ONE line of whatever it is given, like a real agent would.
	d.agentFix = func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		current, err := readUnderRoot(root, req.Path)
		require.NoError(t, err)
		var patched string
		switch {
		case strings.Contains(current, "weak()"):
			patched = strings.Replace(current, "weak();", "SecureRandom fixed;", 1)
		default:
			patched = strings.Replace(current, "insecure();", "AES fixed;", 1)
		}
		return agent.FixResult{Changed: true, PatchedContent: patched}, nil
	}
	d.deliver = func(_ context.Context, _ AutofixOptions, patches []filePatch, _ FindingInputs) (string, error) {
		delivered = patches
		return "https://github.com/o/r/pull/1", nil
	}

	opts := appknoxOpts(root)
	opts.AnalysisID, opts.Repo, opts.PushBranch = 0, "appknox/mfva", true
	_, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)

	require.Len(t, delivered, 1, "one file means one delivered entry, not two that clobber")
	content := delivered[0].Content
	require.Contains(t, content, "SecureRandom fixed", "the first fix must survive")
	require.Contains(t, content, "AES fixed", "the second fix must be present too")
	require.NotContains(t, content, "weak();", "the first finding must actually be fixed")
}

// --push-branch delivers a branch; it must not leave edits in the checkout.
func TestRunAutofix_PushBranch_leavesTheCheckoutClean(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	d := deps(rel, fixResult{Changed: true, PatchedContent: "patched with SecureRandom\n"},
		oneClass("f", "r"))
	opts := appknoxOpts(root)
	opts.Repo, opts.PushBranch = "appknox/mfva", true

	_, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(root, rel))
	require.NoError(t, err)
	require.Equal(t, "orig\n", string(got),
		"fixes are written during the run so they compose, then rolled back")
}
