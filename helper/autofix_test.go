package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/appknox/appknox-go/fixservice"
	"github.com/spf13/viper"
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
	clearCIRepoEnv(t)
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
	require.Equal(t, []string{"Main"}, in.ClassHints)
	require.False(t, called) // flags path must not hit Appknox
}

func TestResolveInputs_FromAppknoxIDs(t *testing.T) {
	fetch := func(_ context.Context, f, a int) (FindingInputs, error) {
		require.Equal(t, 118, f)
		require.Equal(t, 11754, a)
		return FindingInputs{Finding: "Derived Crypto Keys", Remediation: "derive securely"}, nil
	}
	in, err := resolveInputs(context.Background(), AutofixOptions{FileID: 118, AnalysisID: 11754}, fetch)
	require.NoError(t, err)
	require.Equal(t, "derive securely", in.Remediation)
}

func TestResolveInputs_RequiresSomething(t *testing.T) {
	_, err := resolveInputs(context.Background(), AutofixOptions{}, nil)
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
func deps(path string, res fixservice.Result, in FindingInputs) autofixDeps {
	return autofixDeps{
		locate: func(context.Context, agent.Config, agent.Request) (string, error) { return path, nil },
		fetch:  func(context.Context, int, int) (FindingInputs, error) { return in, nil },
		submit: func(context.Context, fixservice.Config, fixservice.Request) (fixservice.Result, error) {
			return res, nil
		},
		agentFix: func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
			return agent.FixResult{Changed: true, PatchedContent: "agent-fixed\n", Diff: "-old\n+new"}, nil
		},
		deliver: func(context.Context, AutofixOptions, []filePatch, FindingInputs) (Delivery, error) {
			return Delivery{URL: "https://github.com/appknox/mfva/compare/master...appknox-autofix/analysis-1?expand=1"}, nil
		},
	}
}

func appknoxOpts(root string) AutofixOptions {
	return AutofixOptions{RepoPath: root, FileID: 1, AnalysisID: 1, FixToken: "tok"}
}

func oneClass(finding, remediation string) FindingInputs {
	return FindingInputs{Finding: finding, ClassHints: []string{"com/x/C"}, Remediation: remediation}
}

func TestRunAutofix_KnoxIQNotCompleted_StopsBeforeFetch(t *testing.T) {
	fetched := false
	d := deps("app/A.java", fixservice.Result{}, oneClass("f", "r"))
	d.knoxiqReady = func(context.Context, int) error {
		return errors.New("knoxiq is not completed for file 1 (sast=Pending, dast=Disabled)")
	}
	d.fetch = func(context.Context, int, int) (FindingInputs, error) {
		fetched = true
		return FindingInputs{}, nil
	}
	_, err := runAutofix(context.Background(), appknoxOpts(t.TempDir()), d)
	require.Error(t, err)
	require.Contains(t, err.Error(), "knoxiq is not completed")
	require.False(t, fetched)
}

func TestRunAutofix_KnoxIQCompleted_Continues(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	checked := 0
	d := deps(rel, fixservice.Result{Changed: true, PatchedContent: "patched\n"}, oneClass("f", "r"))
	d.knoxiqReady = func(_ context.Context, fileID int) error {
		checked++
		require.Equal(t, 1, fileID)
		return nil
	}
	out, err := runAutofix(context.Background(), appknoxOpts(root), d)
	require.NoError(t, err)
	require.Equal(t, 1, checked)
	require.Len(t, out.Patches, 1)
}

func TestRunAutofix_RequiresToken(t *testing.T) {
	t.Setenv("APPKNOX_AUTOFIX_FIX_TOKEN", "")
	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x"}, defaultDeps())
	require.Error(t, err)
}

func TestRunAutofix_UsesResolvedAPIHost(t *testing.T) {
	prev := viper.GetString("host")
	t.Cleanup(func() { viper.Set("host", prev) })
	viper.Set("host", "https://autofix.staging.appknox.io/")

	var got string
	d := deps("", fixservice.Result{}, FindingInputs{})
	d.locate = func(_ context.Context, cfg agent.Config, _ agent.Request) (string, error) {
		got = cfg.Host
		return "", nil
	}
	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x", FixToken: "tok"}, d)
	require.NoError(t, err)
	require.Equal(t, "https://autofix.staging.appknox.io/", got)
}

func TestRunAutofix_RejectsPlaintextRemoteAPIHost(t *testing.T) {
	prev := viper.GetString("host")
	t.Cleanup(func() { viper.Set("host", prev) })
	viper.Set("host", "http://remote.example.com")

	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x", FixToken: "tok"},
		deps("app/A.java", fixservice.Result{}, FindingInputs{}))
	require.Error(t, err)
}

func TestRunAutofix_Advisory_WhenLocateAbstains(t *testing.T) {
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x", FixToken: "tok"},
		deps("", fixservice.Result{}, FindingInputs{}))
	require.NoError(t, err)
	require.Empty(t, out.Located)
}

func TestRunAutofix_LocateOnly_WhenNoRemediation(t *testing.T) {
	root, rel := repoWithFile(t, "orig")
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: root, Finding: "x", FixToken: "tok"},
		deps(rel, fixservice.Result{}, FindingInputs{}))
	require.NoError(t, err)
	require.Equal(t, []string{rel}, out.Located)
	require.Empty(t, out.Patches) // no remediation → no fix
}

func TestRunAutofix_FullFlow_PushesBranch(t *testing.T) {
	root, rel := repoWithFile(t, "int r = new Random().nextInt();\n")
	res := fixservice.Result{Changed: true, PatchedContent: "int r = new SecureRandom().nextInt();\n", Confidence: 0.95}
	out, err := runAutofix(context.Background(), appknoxOpts(root),
		deps(rel, res, oneClass("Insecure Random", "use SecureRandom")))
	require.NoError(t, err)
	require.Len(t, out.Patches, 1)
	require.Contains(t, out.BranchURL, "compare")
	require.False(t, out.Patches[0].Applied)
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Contains(t, string(got), "Random().nextInt") // local checkout is not rewritten
}

func TestRunAutofix_MultiClass_FixesEachLocatedFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	for _, rel := range []string{"app/A.java", "app/B.java"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte("orig\n"), 0o644))
	}
	pathFor := map[string]string{"com/x/A": "app/A.java", "com/x/B": "app/B.java"}
	d := deps("", fixservice.Result{Changed: true, PatchedContent: "fixed\n"}, FindingInputs{})
	d.locate = func(_ context.Context, _ agent.Config, req agent.Request) (string, error) {
		return pathFor[req.ClassHint], nil // each class → its own file
	}
	d.fetch = func(context.Context, int, int) (FindingInputs, error) {
		return FindingInputs{Finding: "Derived Crypto Keys",
			ClassHints: []string{"com/x/A", "com/x/B"}, Remediation: "fix"}, nil
	}
	out, err := runAutofix(context.Background(), appknoxOpts(root), d)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"app/A.java", "app/B.java"}, out.Located)
	require.Len(t, out.Patches, 2)
	require.Contains(t, out.BranchURL, "compare")
	for _, rel := range []string{"app/A.java", "app/B.java"} {
		got, _ := os.ReadFile(filepath.Join(root, rel))
		require.Equal(t, "orig\n", string(got)) // pushed, not written locally
	}
}

func TestRunAutofix_MultiClass_PushBranch_OneBranch(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	for _, rel := range []string{"app/A.java", "app/B.java"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte("orig\n"), 0o644))
	}
	var delivered []filePatch
	d := deps("", fixservice.Result{Changed: true, PatchedContent: "fixed\n"}, FindingInputs{})
	d.locate = func(_ context.Context, _ agent.Config, req agent.Request) (string, error) {
		return map[string]string{"com/x/A": "app/A.java", "com/x/B": "app/B.java"}[req.ClassHint], nil
	}
	d.fetch = func(context.Context, int, int) (FindingInputs, error) {
		return FindingInputs{Finding: "Multi", ClassHints: []string{"com/x/A", "com/x/B"}, Remediation: "fix"}, nil
	}
	d.deliver = func(_ context.Context, _ AutofixOptions, patches []filePatch, _ FindingInputs) (Delivery, error) {
		delivered = patches // all files pushed together in one call
		return Delivery{URL: "https://github.com/o/r/compare/master...b?expand=1"}, nil
	}
	opts := appknoxOpts(root)
	opts.Repo = "appknox/mfva"
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
		deps(rel, fixservice.Result{Changed: true, PatchedContent: "patched\n"}, oneClass("f", "r")))
	require.NoError(t, err)
	require.Len(t, out.Patches, 1)
	require.False(t, out.Patches[0].Applied)
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_PushBranch(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	opts := appknoxOpts(root)
	opts.Repo = "appknox/mfva"
	out, err := runAutofix(context.Background(), opts,
		deps(rel, fixservice.Result{Changed: true, PatchedContent: "patched\n"}, oneClass("f", "r")))
	require.NoError(t, err)
	require.Contains(t, out.BranchURL, "compare")
	require.False(t, out.Patches[0].Applied)
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_PushBranch_ReportsToAppknox(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	del := Delivery{
		URL:    "https://github.com/appknox/mfva/compare/master...appknox-autofix/analysis-1?expand=1",
		Branch: "appknox-autofix/analysis-1", Base: "master",
		CommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	var gotOpts AutofixOptions
	var gotDel Delivery
	var gotPatches []filePatch
	d := deps(rel, fixservice.Result{Changed: true, PatchedContent: "patched\n"}, oneClass("f", "r"))
	d.deliver = func(_ context.Context, _ AutofixOptions, _ []filePatch, _ FindingInputs) (Delivery, error) {
		return del, nil
	}
	d.report = func(_ context.Context, opts AutofixOptions, reported Delivery, patches []filePatch) error {
		gotOpts, gotDel, gotPatches = opts, reported, patches
		return nil
	}
	opts := appknoxOpts(root)
	opts.Repo = "appknox/mfva"
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Equal(t, del.URL, out.BranchURL)
	require.Equal(t, del.CommitSHA, out.CommitSHA)
	require.Equal(t, del.Branch, out.Branch)
	require.Equal(t, 1, gotOpts.FileID)
	require.Equal(t, 1, gotOpts.AnalysisID)
	require.Equal(t, del, gotDel)
	require.Equal(t, rel, gotPatches[0].Path)
}

func TestRunAutofix_PushBranch_ReportError(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	d := deps(rel, fixservice.Result{Changed: true, PatchedContent: "patched\n"}, oneClass("f", "r"))
	d.report = func(context.Context, AutofixOptions, Delivery, []filePatch) error {
		return errors.New("mycroft down")
	}
	opts := appknoxOpts(root)
	opts.Repo = "appknox/mfva"
	_, err := runAutofix(context.Background(), opts, d)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to record on Appknox")
	require.Contains(t, err.Error(), "mycroft down")
}

func TestRunAutofix_AgentFixMode(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	d := deps(rel, fixservice.Result{}, oneClass("f", "r"))
	d.submit = func(context.Context, fixservice.Config, fixservice.Request) (fixservice.Result, error) {
		return fixservice.Result{}, errors.New("server /v1/fix must NOT be called in agent mode")
	}
	opts := appknoxOpts(root)
	opts.FixMode = "agent"
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Len(t, out.Patches, 1)
	require.Equal(t, "agent-fixed\n", out.Patches[0].Content)
	require.Contains(t, out.BranchURL, "compare")
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_EmptyPatchNotApplied(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	out, err := runAutofix(context.Background(), appknoxOpts(root),
		deps(rel, fixservice.Result{Changed: true, PatchedContent: ""}, oneClass("f", "r")))
	require.NoError(t, err)
	require.Empty(t, out.Patches) // empty content is not a patch
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_NoChange_LeavesFile(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	out, err := runAutofix(context.Background(), appknoxOpts(root),
		deps(rel, fixservice.Result{Changed: false}, oneClass("f", "r")))
	require.NoError(t, err)
	require.Empty(t, out.Patches)
	require.Equal(t, []string{rel}, out.Located)
}

func TestRunAutofix_PropagatesSubmitError(t *testing.T) {
	root, rel := repoWithFile(t, "orig")
	d := deps(rel, fixservice.Result{}, oneClass("f", "r"))
	d.submit = func(context.Context, fixservice.Config, fixservice.Request) (fixservice.Result, error) {
		return fixservice.Result{}, errors.New("boom")
	}
	_, err := runAutofix(context.Background(), appknoxOpts(root), d)
	require.Error(t, err)
}
