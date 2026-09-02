package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/stretchr/testify/require"
)

func TestSplitRepo(t *testing.T) {
	o, n, err := splitRepo("appknox/mfva")
	require.NoError(t, err)
	require.Equal(t, "appknox", o)
	require.Equal(t, "mfva", n)
	for _, bad := range []string{"", "noslash", "/name", "owner/", "o/r/x", "o/r?x=1", "o/r evil", "o/r\n"} {
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

func TestListAnalyses_RequiresFileID(t *testing.T) {
	require.Error(t, listAnalyses(0))
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

// deps builds a stub set: locate returns a fixed path, fix returns res, etc.
// fixResult carries what a stub fix produced. It replaces the old fixservice
// payload type, which went away with the upload path.
type fixResult struct {
	Changed        bool
	PatchedContent string
	UnifiedDiff    string
	Confidence     float64
}

func deps(path string, res fixResult, in FindingInputs) autofixDeps {
	return autofixDeps{
		locate: func(context.Context, agent.Config, agent.Request) (string, error) { return path, nil },
		fetch:  func(context.Context, int, int) (FindingInputs, error) { return in, nil },
		agentFix: func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
			return agent.FixResult{
				Changed: res.Changed, PatchedContent: res.PatchedContent, Diff: res.UnifiedDiff}, nil
		},
		deliver: func(context.Context, AutofixOptions, []filePatch, FindingInputs) (string, error) {
			return "https://github.com/appknox/mfva/compare/master...appknox-autofix/analysis-1?expand=1", nil
		},
	}
}

func appknoxOpts(root string) AutofixOptions {
	return AutofixOptions{RepoPath: root, FileID: 1, AnalysisID: 1, FixToken: "tok"}
}

// oneClass carries a KnoxIQ criterion too: delivery is now gated on the patch
// satisfying one, so a fixture without criteria would be refused.
func oneClass(finding, remediation string) FindingInputs {
	return FindingInputs{
		Finding: finding, ClassHints: []string{"com/x/C"}, Remediation: remediation,
		Criteria: []string{"Confirm SecureRandom is present"},
	}
}

func TestRunAutofix_RequiresToken(t *testing.T) {
	t.Setenv("APPKNOX_AUTOFIX_FIX_TOKEN", "")
	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x"}, defaultDeps())
	require.Error(t, err)
}

func TestRunAutofix_RejectsPlaintextRemoteFixURL(t *testing.T) {
	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x", FixToken: "tok", FixURL: "http://gateway.example.com"},
		deps("app/A.java", fixResult{}, FindingInputs{}))
	require.Error(t, err)
}

func TestRunAutofix_Advisory_WhenLocateAbstains(t *testing.T) {
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x", FixToken: "tok"},
		deps("", fixResult{}, FindingInputs{}))
	require.NoError(t, err)
	require.Empty(t, out.Located)
}

func TestRunAutofix_LocateOnly_WhenNoRemediation(t *testing.T) {
	root, rel := repoWithFile(t, "orig")
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: root, Finding: "x", FixToken: "tok"},
		deps(rel, fixResult{}, FindingInputs{}))
	require.NoError(t, err)
	require.Equal(t, []string{rel}, out.Located)
	require.Empty(t, out.Patches) // no remediation → no fix
}

func TestRunAutofix_FullFlow_AppliesPatch(t *testing.T) {
	root, rel := repoWithFile(t, "int r = new Random().nextInt();\n")
	res := fixResult{Changed: true, PatchedContent: "int r = new SecureRandom().nextInt();\n", Confidence: 0.95}
	out, err := runAutofix(context.Background(), appknoxOpts(root),
		deps(rel, res, oneClass("Insecure Random", "use SecureRandom")))
	require.NoError(t, err)
	require.Len(t, out.Patches, 1)
	require.True(t, out.Patches[0].Applied)
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Contains(t, string(got), "SecureRandom")
}

func TestRunAutofix_MultiClass_FixesEachLocatedFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	for _, rel := range []string{"app/A.java", "app/B.java"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte("orig\n"), 0o644))
	}
	pathFor := map[string]string{"com/x/A": "app/A.java", "com/x/B": "app/B.java"}
	d := deps("", fixResult{Changed: true, PatchedContent: "fixed with SecureRandom\n"}, FindingInputs{})
	d.locate = func(_ context.Context, _ agent.Config, req agent.Request) (string, error) {
		return pathFor[req.ClassHint], nil // each class → its own file
	}
	d.fetch = func(context.Context, int, int) (FindingInputs, error) {
		return FindingInputs{Finding: "Derived Crypto Keys",
			ClassHints: []string{"com/x/A", "com/x/B"}, Remediation: "fix",
			Criteria: []string{"Confirm SecureRandom is present"}}, nil
	}
	out, err := runAutofix(context.Background(), appknoxOpts(root), d)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"app/A.java", "app/B.java"}, out.Located)
	require.Len(t, out.Patches, 2)
	for _, rel := range []string{"app/A.java", "app/B.java"} {
		got, _ := os.ReadFile(filepath.Join(root, rel))
		require.Equal(t, "fixed with SecureRandom\n", string(got)) // BOTH classes fixed
	}
}

func TestRunAutofix_MultiClass_PushBranch_OneBranch(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	for _, rel := range []string{"app/A.java", "app/B.java"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte("orig\n"), 0o644))
	}
	var delivered []filePatch
	d := deps("", fixResult{Changed: true, PatchedContent: "fixed with SecureRandom\n"}, FindingInputs{})
	d.locate = func(_ context.Context, _ agent.Config, req agent.Request) (string, error) {
		return map[string]string{"com/x/A": "app/A.java", "com/x/B": "app/B.java"}[req.ClassHint], nil
	}
	d.fetch = func(context.Context, int, int) (FindingInputs, error) {
		return FindingInputs{Finding: "Multi", ClassHints: []string{"com/x/A", "com/x/B"}, Remediation: "fix",
			Criteria: []string{"Confirm SecureRandom is present"}}, nil
	}
	d.deliver = func(_ context.Context, _ AutofixOptions, patches []filePatch, _ FindingInputs) (string, error) {
		delivered = patches // all files pushed together in one call
		return "https://github.com/o/r/compare/master...b?expand=1", nil
	}
	opts := appknoxOpts(root)
	opts.Repo, opts.PushBranch = "appknox/mfva", true
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Len(t, delivered, 2) // both files in ONE deliver call → one branch
	require.Contains(t, out.BranchURL, "compare")
}

func TestRunAutofix_DryRun_DoesNotWrite(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	opts := appknoxOpts(root)
	opts.DryRun = true
	out, err := runAutofix(context.Background(), opts,
		deps(rel, fixResult{Changed: true, PatchedContent: "patched with SecureRandom\n"}, oneClass("f", "r")))
	require.NoError(t, err)
	require.Len(t, out.Patches, 1)
	require.False(t, out.Patches[0].Applied)
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_PushBranch(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	opts := appknoxOpts(root)
	opts.Repo, opts.PushBranch = "appknox/mfva", true
	out, err := runAutofix(context.Background(), opts,
		deps(rel, fixResult{Changed: true, PatchedContent: "patched with SecureRandom\n"}, oneClass("f", "r")))
	require.NoError(t, err)
	require.Contains(t, out.BranchURL, "compare")
	require.False(t, out.Patches[0].Applied) // delivered as a branch, not applied locally
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_EmptyPatchNotApplied(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	out, err := runAutofix(context.Background(), appknoxOpts(root),
		deps(rel, fixResult{Changed: true, PatchedContent: ""}, oneClass("f", "r")))
	require.NoError(t, err)
	require.Empty(t, out.Patches) // empty content is not a patch
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_NoChange_LeavesFile(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	out, err := runAutofix(context.Background(), appknoxOpts(root),
		deps(rel, fixResult{Changed: false}, oneClass("f", "r")))
	require.NoError(t, err)
	require.Empty(t, out.Patches)
	require.Equal(t, []string{rel}, out.Located)
}

func TestRunAutofix_PropagatesFixError(t *testing.T) {
	root, rel := repoWithFile(t, "orig")
	d := deps(rel, fixResult{}, oneClass("f", "r"))
	d.agentFix = func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
		return agent.FixResult{}, errors.New("boom")
	}
	_, err := runAutofix(context.Background(), appknoxOpts(root), d)
	require.Error(t, err)
}
