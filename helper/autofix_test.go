package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/appknox/appknox-go/fixservice"
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
	cleanup()
	require.DirExists(t, dir)
}

func TestResolveRepoRoot_RequiresRepoOrPath(t *testing.T) {
	_, _, err := resolveRepoRoot(context.Background(), AutofixOptions{})
	require.Error(t, err)
}

func TestResolveInputs_FromFlags(t *testing.T) {
	called := false
	fetch := func(context.Context, int, int) (FindingInputs, error) { called = true; return FindingInputs{}, nil }
	in, err := resolveInputs(context.Background(),
		AutofixOptions{Finding: "weak PRNG", ClassHint: "Main"}, fetch)
	require.NoError(t, err)
	require.Equal(t, "weak PRNG", in.Finding)
	require.False(t, called) // flags path must not hit Appknox
}

func TestResolveInputs_FromAppknoxIDs(t *testing.T) {
	fetch := func(_ context.Context, f, a int) (FindingInputs, error) {
		require.Equal(t, 118, f)
		require.Equal(t, 11829, a)
		return FindingInputs{Finding: "Insecure Random", Remediation: "use SecureRandom"}, nil
	}
	in, err := resolveInputs(context.Background(), AutofixOptions{FileID: 118, AnalysisID: 11829}, fetch)
	require.NoError(t, err)
	require.Equal(t, "use SecureRandom", in.Remediation)
}

func TestResolveInputs_RequiresSomething(t *testing.T) {
	_, err := resolveInputs(context.Background(), AutofixOptions{}, nil)
	require.Error(t, err)
}

// repoWithFile makes a checkout with one file and returns (root, relpath).
func repoWithFile(t *testing.T, body string) (string, string) {
	t.Helper()
	root := t.TempDir()
	rel := "app/src/main/java/com/appknox/mfva/MainActivity.java"
	require.NoError(t, os.MkdirAll(filepath.Join(root, filepath.Dir(rel)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte(body), 0o644))
	return root, rel
}

func deps(path string, res fixservice.Result, in FindingInputs) autofixDeps {
	return autofixDeps{
		locate: func(context.Context, agent.Config, agent.Request) (string, error) { return path, nil },
		fetch:  func(context.Context, int, int) (FindingInputs, error) { return in, nil },
		submit: func(context.Context, fixservice.Config, fixservice.Request) (fixservice.Result, error) { return res, nil },
	}
}

func TestRunAutofix_RequiresToken(t *testing.T) {
	t.Setenv("APPKNOX_AUTOFIX_FIX_TOKEN", "")
	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x"}, defaultDeps())
	require.Error(t, err)
}

func TestRunAutofix_RejectsPlaintextRemoteFixURL(t *testing.T) {
	// A remote http:// fix-url must be rejected BEFORE locate (token would leak).
	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x", FixToken: "tok", FixURL: "http://gateway.example.com"},
		deps("app/A.java", fixservice.Result{}, FindingInputs{}))
	require.Error(t, err)
}

func TestRunAutofix_Advisory_WhenLocateAbstains(t *testing.T) {
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x", FixToken: "tok"},
		deps("", fixservice.Result{}, FindingInputs{}))
	require.NoError(t, err)
	require.False(t, out.Located)
}

func TestRunAutofix_LocateOnly_WhenNoRemediation(t *testing.T) {
	root, rel := repoWithFile(t, "orig")
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: root, Finding: "x", FixToken: "tok"},
		deps(rel, fixservice.Result{}, FindingInputs{Finding: "x"}))
	require.NoError(t, err)
	require.True(t, out.Located)
	require.Nil(t, out.Result) // no remediation → no fix call
}

func TestRunAutofix_FullFlow_AppliesPatch(t *testing.T) {
	root, rel := repoWithFile(t, "int r = new Random().nextInt();\n")
	res := fixservice.Result{Changed: true, PatchedContent: "int r = new SecureRandom().nextInt();\n", Confidence: 0.95}
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: root, FileID: 1, AnalysisID: 1, FixToken: "tok"},
		deps(rel, res, FindingInputs{Finding: "Insecure Random", Remediation: "use SecureRandom"}))
	require.NoError(t, err)
	require.True(t, out.Applied)
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Contains(t, string(got), "SecureRandom")
}

func TestRunAutofix_DryRun_DoesNotWrite(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	res := fixservice.Result{Changed: true, PatchedContent: "patched\n"}
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: root, FileID: 1, AnalysisID: 1, FixToken: "tok", DryRun: true},
		deps(rel, res, FindingInputs{Finding: "f", Remediation: "r"}))
	require.NoError(t, err)
	require.False(t, out.Applied)
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got)) // unchanged
}

func TestRunAutofix_NoChange_LeavesFile(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: root, FileID: 1, AnalysisID: 1, FixToken: "tok"},
		deps(rel, fixservice.Result{Changed: false}, FindingInputs{Finding: "f", Remediation: "r"}))
	require.NoError(t, err)
	require.False(t, out.Applied)
	require.NotNil(t, out.Result)
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_EmptyPatchNotApplied(t *testing.T) {
	// changed=true but empty patched_content must NOT clobber the source.
	root, rel := repoWithFile(t, "orig\n")
	res := fixservice.Result{Changed: true, PatchedContent: ""}
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: root, FileID: 1, AnalysisID: 1, FixToken: "tok"},
		deps(rel, res, FindingInputs{Finding: "f", Remediation: "r"}))
	require.NoError(t, err)
	require.False(t, out.Applied)
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_PropagatesSubmitError(t *testing.T) {
	root, rel := repoWithFile(t, "orig")
	d := deps(rel, fixservice.Result{}, FindingInputs{Finding: "f", Remediation: "r"})
	d.submit = func(context.Context, fixservice.Config, fixservice.Request) (fixservice.Result, error) {
		return fixservice.Result{}, errors.New("boom")
	}
	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: root, FileID: 1, AnalysisID: 1, FixToken: "tok"}, d)
	require.Error(t, err)
}
