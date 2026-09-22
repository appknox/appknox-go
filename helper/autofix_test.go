package helper

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/appknox/appknox-go/agent"
	"github.com/appknox/appknox-go/appknox"
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

// resolveInputs / fetchAppknoxInputs were replaced by resolveTargets / the
// KnoxIQ-backed fetch. Their old coverage now lives in
// helper/autofix_targets_test.go:
//   - "flags path must not hit Appknox"  -> TestResolveTargets_ManualFindingNeedsNoLookup
//   - "FileID path derives from Appknox" -> TestResolveTargets_KeepsOnlyAnalysesKnoxIQCanFix,
//     TestResolveTargets_SingleAnalysisMode
//   - "requires FileID or Finding"       -> TestResolveTargets_RequiresFileIDOrFinding

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
// analysisIDs reports a single analysis (id 1); fetch returns in for it
// regardless of which analysis id it is asked about, mirroring the single
// FindingInputs a real single-analysis file used to produce.
func deps(path string, res fixservice.Result, in FindingInputs) autofixDeps {
	return autofixDeps{
		locate:      func(context.Context, agent.Config, agent.Request) (string, error) { return path, nil },
		analysisIDs: func(context.Context, int, int) ([]int, error) { return []int{1}, nil },
		fetch:       func(context.Context, int, int) (FindingInputs, error) { return in, nil },
		submit: func(context.Context, fixservice.Config, fixservice.Request) (fixservice.Result, error) {
			return res, nil
		},
		agentFix: func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
			return agent.FixResult{Changed: true, PatchedContent: "agent-fixed\n", Diff: "-old\n+new"}, nil
		},
		deliver: func(context.Context, AutofixOptions, []filePatch) (Delivery, error) {
			return Delivery{URL: "https://github.com/appknox/mfva/pull/1"}, nil
		},
	}
}

func withAccessToken(t *testing.T) {
	t.Helper()
	prev := viper.GetString("access-token")
	viper.Set("access-token", "tok")
	t.Cleanup(func() { viper.Set("access-token", prev) })
}

func appknoxOpts(t *testing.T, root string) AutofixOptions {
	t.Helper()
	withAccessToken(t)
	return AutofixOptions{RepoPath: root, FileID: 1}
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
	_, err := runAutofix(context.Background(), appknoxOpts(t, t.TempDir()), d)
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
	out, err := runAutofix(context.Background(), appknoxOpts(t, root), d)
	require.NoError(t, err)
	require.Equal(t, 1, checked)
	require.Len(t, out.Patches, 1)
}

// TestRunAutofix_DefaultsRiskThresholdToOne is the regression test for the
// RiskThreshold default. locatableAnalysisIDs keeps analyses with
// ComputedRisk >= riskThreshold, and AutofixOptions.RiskThreshold's zero
// value is 0 ("everything", Passed analyses included) -- on a real file most
// analyses ARE Passed, so an unset threshold would multiply KnoxIQ round
// trips roughly 4-5x against a gateway with a real per-session call budget.
// runAutofix must turn an unset (<=0) RiskThreshold into 1 before it reaches
// d.analysisIDs.
func TestRunAutofix_DefaultsRiskThresholdToOne(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	var gotThreshold int
	d := deps(rel, fixservice.Result{Changed: true, PatchedContent: "patched\n"}, oneClass("f", "r"))
	d.analysisIDs = func(_ context.Context, _, riskThreshold int) ([]int, error) {
		gotThreshold = riskThreshold
		return []int{1}, nil
	}
	_, err := runAutofix(context.Background(), appknoxOpts(t, root), d)
	require.NoError(t, err)
	require.Equal(t, 1, gotThreshold)
}

// TestRunAutofix_PreservesAnExplicitRiskThreshold guards the other half of
// the same fix: the default must not clobber a threshold the caller actually
// set (a future --risk-threshold flag, or health-score mode).
func TestRunAutofix_PreservesAnExplicitRiskThreshold(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	var gotThreshold int
	d := deps(rel, fixservice.Result{Changed: true, PatchedContent: "patched\n"}, oneClass("f", "r"))
	d.analysisIDs = func(_ context.Context, _, riskThreshold int) ([]int, error) {
		gotThreshold = riskThreshold
		return []int{1}, nil
	}
	opts := appknoxOpts(t, root)
	opts.RiskThreshold = 3
	_, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Equal(t, 3, gotThreshold)
}

// TestMemoizedAnalysesFor_ListsOncePerFileID is M2: the regression test for
// the caching contract the whole fetch/analysisIDs signature change exists to
// support. fetchKnoxIQInputs is called once per analysis target (up to ~18 on
// a real scan), and AnalysesService has no GetByID, only ListByFile, so
// without this cache every one of those calls would re-list the whole file.
// This pins that N repeated lookups for the same fileID hit the underlying
// list function exactly once.
func TestMemoizedAnalysesFor_ListsOncePerFileID(t *testing.T) {
	calls := 0
	list := func(context.Context, int) ([]*appknox.Analysis, error) {
		calls++
		return []*appknox.Analysis{{ID: 1}, {ID: 2}, {ID: 3}}, nil
	}
	analysesFor := memoizedAnalysesFor(list)

	const n = 5 // simulates N analyses on the same file, e.g. everyLocatableAnalysis's fetch loop
	for i := 0; i < n; i++ {
		_, err := analysesFor(context.Background(), 24)
		require.NoError(t, err)
	}
	require.Equal(t, 1, calls, "N lookups for the same fileID must hit the underlying list exactly once")
}

// TestMemoizedAnalysesFor_CachesPerFileID guards against a cache keyed
// wrong: two different fileIDs must each get their own underlying list call,
// not share one.
func TestMemoizedAnalysesFor_CachesPerFileID(t *testing.T) {
	var seen []int
	list := func(_ context.Context, fileID int) ([]*appknox.Analysis, error) {
		seen = append(seen, fileID)
		return nil, nil
	}
	analysesFor := memoizedAnalysesFor(list)

	_, err := analysesFor(context.Background(), 24)
	require.NoError(t, err)
	_, err = analysesFor(context.Background(), 118)
	require.NoError(t, err)
	_, err = analysesFor(context.Background(), 24)
	require.NoError(t, err)

	require.Equal(t, []int{24, 118}, seen, "each distinct fileID is listed once, not re-listed")
}

// TestWithKnoxIQFetchers_FillsOnlyWhicheverFieldWasNil documents the
// current contract of withKnoxIQFetchers: a caller that stubs only ONE of
// autofixDeps' fetch/analysisIDs fields still gets the real implementation
// for the OTHER, and the caller's own stub survives untouched.
//
// It is NOT a regression guard for I3 (the removed `d.fetch != nil &&
// d.analysisIDs != nil { return d }` early return) and will NOT fail if
// that early return is restored: both subtests below stub exactly one
// field, so the early return's condition (both non-nil) is never true
// either way, and this test cannot observe whether it is present. I3 was a
// readability/trap fix -- the early return was redundant and its removal
// changed no observable behaviour -- so there is nothing behavioural here
// to assert a regression against. Do not read a future failure of this
// test as evidence that I3 regressed; it can only fail if
// withKnoxIQFetchers stops filling a nil field independently.
func TestWithKnoxIQFetchers_FillsOnlyWhicheverFieldWasNil(t *testing.T) {
	onlyAnalysisIDs := autofixDeps{
		analysisIDs: func(context.Context, int, int) ([]int, error) { return []int{1}, nil },
	}
	filled := withKnoxIQFetchers(onlyAnalysisIDs)
	require.NotNil(t, filled.fetch, "fetch must be filled in when only analysisIDs was stubbed")
	require.NotNil(t, filled.analysisIDs, "the caller's own analysisIDs stub must survive")

	onlyFetch := autofixDeps{
		fetch: func(context.Context, int, int) (FindingInputs, error) { return FindingInputs{}, nil },
	}
	filled2 := withKnoxIQFetchers(onlyFetch)
	require.NotNil(t, filled2.analysisIDs, "analysisIDs must be filled in when only fetch was stubbed")
	require.NotNil(t, filled2.fetch, "the caller's own fetch stub must survive")
}

func TestRunAutofix_RequiresToken(t *testing.T) {
	prev := viper.GetString("access-token")
	t.Cleanup(func() { viper.Set("access-token", prev) })
	viper.Set("access-token", "")
	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x"}, defaultDeps())
	require.Error(t, err)
	require.Contains(t, err.Error(), "APPKNOX_ACCESS_TOKEN")
}

func TestRunAutofix_UsesResolvedAPIHost(t *testing.T) {
	withAccessToken(t)
	prev := viper.GetString("host")
	t.Cleanup(func() { viper.Set("host", prev) })
	viper.Set("host", "https://autofix.staging.appknox.io/")

	var gotHost, gotToken string
	d := deps("", fixservice.Result{}, FindingInputs{})
	d.locate = func(_ context.Context, cfg agent.Config, _ agent.Request) (string, error) {
		gotHost, gotToken = cfg.Host, cfg.Token
		return "", nil
	}
	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x"}, d)
	require.NoError(t, err)
	require.Equal(t, "https://autofix.staging.appknox.io/", gotHost)
	require.Equal(t, "tok", gotToken)
}

func TestRunAutofix_RejectsPlaintextRemoteAPIHost(t *testing.T) {
	withAccessToken(t)
	prev := viper.GetString("host")
	t.Cleanup(func() { viper.Set("host", prev) })
	viper.Set("host", "http://remote.example.com")

	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x"},
		deps("app/A.java", fixservice.Result{}, FindingInputs{}))
	require.Error(t, err)
}

func TestRunAutofix_Advisory_WhenLocateAbstains(t *testing.T) {
	withAccessToken(t)
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), Finding: "x"},
		deps("", fixservice.Result{}, FindingInputs{}))
	require.NoError(t, err)
	require.Empty(t, out.Located)
}

func TestRunAutofix_LocateOnly_WhenNoRemediation(t *testing.T) {
	withAccessToken(t)
	root, rel := repoWithFile(t, "orig")
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: root, Finding: "x"},
		deps(rel, fixservice.Result{}, FindingInputs{}))
	require.NoError(t, err)
	require.Equal(t, []string{rel}, out.Located)
	require.Empty(t, out.Patches) // no remediation → no fix
}

// TestRun_EmptyRemediationNeverReachesTheFixer is the regression test for the
// `|| in.Remediation == ""` guard in fixSession.run. That guard looks
// redundant on the automatic --file-id path (everyLocatableAnalysis already
// filters empty Remediation before a target exists), but resolveTargets does
// NOT guarantee it for a manual --finding target (Remediation is never set at
// all) or a --file-id + --analysis-id target (whatever d.fetch returned,
// unfiltered). Deleting the guard again must fail THIS test even though every
// --file-id-only test above would keep passing.
func TestRun_EmptyRemediationNeverReachesTheFixer(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	agentFixCalled := false
	d := autofixDeps{
		locate: func(context.Context, agent.Config, agent.Request) (string, error) { return rel, nil },
		agentFix: func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
			agentFixCalled = true
			return agent.FixResult{Changed: true, PatchedContent: "must never be produced\n"}, nil
		},
	}
	s := fixSession{
		opts: AutofixOptions{FixMode: "agent", FileID: 1},
		d:    d,
		root: root,
		targets: []analysisTarget{
			{AnalysisID: 1, Inputs: FindingInputs{
				Finding: "no remediation", ClassHints: []string{"Main"}, Remediation: "",
			}},
		},
	}
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{rel}, out.Located, "an empty-Remediation target is still located and reported")
	require.Empty(t, out.Patches)
	require.False(t, agentFixCalled,
		"the fixer must never be called for a target whose Remediation is empty")
}

// TestLocateAll_EmptyClassHintsStillLocatesOnce is the regression test for
// C1: knoxIQInputs derives ClassHints with the same class-descriptor regex
// the targeting layer was explicitly built to stop requiring, so a manifest /
// network-config / permission finding routinely has ZERO class hints. Before
// this fix, looping over in.ClassHints meant such a target made zero locate
// calls and was silently dropped at the len(paths) == 0 guard in run() --
// the class-descriptor precondition surviving one layer below resolveTargets,
// undoing the whole point of the port. A hint-less finding must still get
// exactly one locate attempt, with an empty ClassHint, so the locate agent
// can work from the finding text alone.
func TestLocateAll_EmptyClassHintsStillLocatesOnce(t *testing.T) {
	var calls int
	var gotHint string
	s := fixSession{
		d: autofixDeps{
			locate: func(_ context.Context, _ agent.Config, req agent.Request) (string, error) {
				calls++
				gotHint = req.ClassHint
				return "app/src/main/AndroidManifest.xml", nil
			},
		},
	}
	paths, err := s.locateAll(context.Background(),
		FindingInputs{Finding: "Application Data Backup Allowed"})
	require.NoError(t, err)
	require.Equal(t, 1, calls, "a hint-less finding must still get exactly one locate call")
	require.Equal(t, "", gotHint, "the hint-less pass must carry an empty ClassHint")
	require.Equal(t, []string{"app/src/main/AndroidManifest.xml"}, paths)
}

func TestRunAutofix_FullFlow_PushesBranch(t *testing.T) {
	root, rel := repoWithFile(t, "int r = new Random().nextInt();\n")
	res := fixservice.Result{Changed: true, PatchedContent: "int r = new SecureRandom().nextInt();\n", Confidence: 0.95}
	out, err := runAutofix(context.Background(), appknoxOpts(t, root),
		deps(rel, res, oneClass("Insecure Random", "use SecureRandom")))
	require.NoError(t, err)
	require.Len(t, out.Patches, 1)
	require.Contains(t, out.BranchURL, "/pull/")
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
	out, err := runAutofix(context.Background(), appknoxOpts(t, root), d)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"app/A.java", "app/B.java"}, out.Located)
	require.Len(t, out.Patches, 2)
	require.Contains(t, out.BranchURL, "/pull/")
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
	d.deliver = func(_ context.Context, _ AutofixOptions, patches []filePatch) (Delivery, error) {
		delivered = patches // all files pushed together in one call
		return Delivery{URL: "https://github.com/o/r/pull/1"}, nil
	}
	opts := appknoxOpts(t, root)
	opts.Repo = "appknox/mfva"
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Len(t, delivered, 2) // both files in ONE deliver call → one branch
	require.Contains(t, out.BranchURL, "/pull/")
}

func TestRunAutofix_DryRun_DoesNotWrite(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	opts := appknoxOpts(t, root)
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
	opts := appknoxOpts(t, root)
	opts.Repo = "appknox/mfva"
	out, err := runAutofix(context.Background(), opts,
		deps(rel, fixservice.Result{Changed: true, PatchedContent: "patched\n"}, oneClass("f", "r")))
	require.NoError(t, err)
	require.Contains(t, out.BranchURL, "/pull/")
	require.False(t, out.Patches[0].Applied)
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_PushBranch_ReportsToAppknox(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	del := Delivery{
		URL:    "https://github.com/appknox/mfva/pull/1",
		Branch: "appknox-autofix/analysis-1", Base: "master",
		CommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	var gotOpts AutofixOptions
	var gotDel Delivery
	var gotPatches []filePatch
	d := deps(rel, fixservice.Result{Changed: true, PatchedContent: "patched\n"}, oneClass("f", "r"))
	d.deliver = func(_ context.Context, _ AutofixOptions, _ []filePatch) (Delivery, error) {
		return del, nil
	}
	d.report = func(_ context.Context, opts AutofixOptions, reported Delivery, patches []filePatch) error {
		gotOpts, gotDel, gotPatches = opts, reported, patches
		return nil
	}
	opts := appknoxOpts(t, root)
	opts.Repo = "appknox/mfva"
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Equal(t, del.URL, out.BranchURL)
	require.Equal(t, del.CommitSHA, out.CommitSHA)
	require.Equal(t, del.Branch, out.Branch)
	require.Equal(t, 1, gotOpts.FileID)
	require.Equal(t, del, gotDel)
	require.Equal(t, rel, gotPatches[0].Path)
}

func TestRunAutofix_PushBranch_ReportError(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	d := deps(rel, fixservice.Result{Changed: true, PatchedContent: "patched\n"}, oneClass("f", "r"))
	d.report = func(context.Context, AutofixOptions, Delivery, []filePatch) error {
		return errors.New("mycroft down")
	}
	opts := appknoxOpts(t, root)
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
	opts := appknoxOpts(t, root)
	opts.FixMode = "agent"
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Len(t, out.Patches, 1)
	require.Equal(t, "agent-fixed\n", out.Patches[0].Content)
	require.Contains(t, out.BranchURL, "/pull/")
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_EmptyPatchNotApplied(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	out, err := runAutofix(context.Background(), appknoxOpts(t, root),
		deps(rel, fixservice.Result{Changed: true, PatchedContent: ""}, oneClass("f", "r")))
	require.NoError(t, err)
	require.Empty(t, out.Patches) // empty content is not a patch
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_NoChange_LeavesFile(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	out, err := runAutofix(context.Background(), appknoxOpts(t, root),
		deps(rel, fixservice.Result{Changed: false}, oneClass("f", "r")))
	require.NoError(t, err)
	require.Empty(t, out.Patches)
	require.Equal(t, []string{rel}, out.Located)
}

func TestRunAutofix_FileID_SkipsFailedFinding(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app/A.java"), []byte("orig\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app/B.java"), []byte("orig\n"), 0o644))
	d := deps("", fixservice.Result{Changed: true, PatchedContent: "fixed\n"}, FindingInputs{})
	d.locate = func(_ context.Context, _ agent.Config, req agent.Request) (string, error) {
		return map[string]string{"com/x/A": "app/A.java", "com/x/B": "app/B.java"}[req.ClassHint], nil
	}
	d.analysisIDs = func(context.Context, int, int) ([]int, error) { return []int{1, 2}, nil }
	d.fetch = func(_ context.Context, _, analysisID int) (FindingInputs, error) {
		if analysisID == 1 {
			return FindingInputs{Finding: "Bad", ClassHints: []string{"com/x/A"}, Remediation: "fix"}, nil
		}
		return FindingInputs{Finding: "Good", ClassHints: []string{"com/x/B"}, Remediation: "fix"}, nil
	}
	d.submit = func(_ context.Context, _ fixservice.Config, req fixservice.Request) (fixservice.Result, error) {
		if req.Finding == "Bad" {
			return fixservice.Result{}, errors.New("model failed")
		}
		return fixservice.Result{Changed: true, PatchedContent: "fixed\n"}, nil
	}
	out, err := runAutofix(context.Background(), appknoxOpts(t, root), d)
	require.NoError(t, err)
	require.Len(t, out.Patches, 1)
	require.Equal(t, "app/B.java", out.Patches[0].Path)
	require.Contains(t, out.BranchURL, "/pull/")
}

func TestAwaitAutofix_NilClient(t *testing.T) {
	_, err := awaitAutofix(context.Background(), nil, 118)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing Appknox client")
}

func TestAwaitAutofix_ProcessedOnStart(t *testing.T) {
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/knoxiq/file/118/autofix", r.URL.Path)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 12, "file": 118, "project": 45, "status": "Processed",
			"pr_url": "https://github.com/appknox/mfva/pull/16",
		})
	})
	req, err := awaitAutofix(context.Background(), client, 118)
	require.NoError(t, err)
	require.Equal(t, "Processed", req.Status)
	require.Equal(t, "https://github.com/appknox/mfva/pull/16", req.PRURL)
}

func TestAwaitAutofix_ProcessingOnStart(t *testing.T) {
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/knoxiq/file/118/autofix", r.URL.Path)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 12, "file": 118, "project": 45, "status": "Processing",
		})
	})
	req, err := awaitAutofix(context.Background(), client, 118)
	require.NoError(t, err)
	require.Equal(t, "Processing", req.Status)
}

func TestAwaitAutofix_PollsUntilProcessing(t *testing.T) {
	prevSleep := autofixSleep
	t.Cleanup(func() { autofixSleep = prevSleep })
	autofixSleep = func(time.Duration) {}

	n := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/knoxiq/file/118/autofix", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 12, "file": 118, "project": 45, "status": "Pending",
		})
	})
	mux.HandleFunc("/api/knoxiq/file/118/autofix/status", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		n++
		status := "Pending"
		if n >= 2 {
			status = "Processing"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 12, "file": 118, "project": 45, "status": status,
		})
	})
	client := testAppknoxClient(t, mux.ServeHTTP)
	req, err := awaitAutofix(context.Background(), client, 118)
	require.NoError(t, err)
	require.Equal(t, "Processing", req.Status)
	require.GreaterOrEqual(t, n, 2)
}

func TestAwaitAutofix_Errored(t *testing.T) {
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 12, "file": 118, "project": 45, "status": "Errored",
			"error_message": "Sherrinford is unavailable",
		})
	})
	_, err := awaitAutofix(context.Background(), client, 118)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Sherrinford is unavailable")
}

func TestAwaitAutofix_Timeout(t *testing.T) {
	marked := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/knoxiq/file/118/autofix/timeout", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		marked = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 12, "file": 118, "project": 45, "status": "Timed Out",
		})
	})
	mux.HandleFunc("/api/knoxiq/file/118/autofix", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 12, "file": 118, "project": 45, "status": "Pending",
		})
	})
	client := testAppknoxClient(t, mux.ServeHTTP)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := awaitAutofix(ctx, client, 118)
	require.EqualError(t, err, "autofix timed out for file 118 after 1h0m0s")
	require.True(t, marked)
}

func TestAwaitAutofix_AlreadyTimedOut(t *testing.T) {
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 12, "file": 118, "project": 45, "status": "Timed Out",
		})
	})
	_, err := awaitAutofix(context.Background(), client, 118)
	require.EqualError(t, err, "autofix timed out for file 118 after 1h0m0s")
}

func TestAwaitAutofix_StartError(t *testing.T) {
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "denied"})
	})
	_, err := awaitAutofix(context.Background(), client, 118)
	require.Error(t, err)
	require.Contains(t, err.Error(), "autofix start failed")
}

func TestPrAction(t *testing.T) {
	require.Equal(t, "Created PR", prAction(true))
	require.Equal(t, "Updated PR", prAction(false))
}
