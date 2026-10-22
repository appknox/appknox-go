package helper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/appknox/appknox-go/agent"
	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
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

// deps builds a stub set: locate answers with path, fix returns res, and
// delivery opens a fake pull request.
func deps(path string, res fixResult) autofixDeps {
	return autofixDeps{
		locate: targetsAt(path),
		fix: func(context.Context, string, targetContext, *patchViolation) (fixResult, error) {
			return res, nil
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
	return AutofixOptions{RepoPath: root, FileID: 1, Units: jobUnits("f")}
}

// jobUnits is what a Mycroft worker publishes: one fixable finding per name,
// with unit id "u-<name>".
func jobUnits(findings ...string) *[]appknox.AutofixUnit {
	units := make([]appknox.AutofixUnit, 0, len(findings))
	for _, f := range findings {
		units = append(units, appknox.AutofixUnit{UnitID: "u-" + f, Finding: f})
	}
	return &units
}

// oneClass is one finding with a single unit, as targetsFromUnits builds it.
func oneClass(finding string) FindingInputs {
	return FindingInputs{Finding: finding, UnitID: "u-" + finding,
		Units: []FindingUnit{{UnitID: "u-" + finding}}}
}

func TestRunAutofix_KnoxIQNotCompleted_StopsBeforeLocate(t *testing.T) {
	located := false
	d := deps("app/A.java", fixResult{})
	d.knoxiqReady = func(context.Context, int) error {
		return errors.New("knoxiq is not completed for file 1 (sast=Pending, dast=Disabled)")
	}
	d.locate = func(context.Context, FindingUnit) (agent.TargetReply, error) {
		located = true
		return agent.TargetReply{}, nil
	}
	_, err := runAutofix(context.Background(), appknoxOpts(t, t.TempDir()), d)
	require.Error(t, err)
	require.Contains(t, err.Error(), "knoxiq is not completed")
	require.False(t, located)
}

func TestRunAutofix_RequiresAJob(t *testing.T) {
	withAccessToken(t)
	_, err := runAutofix(context.Background(), AutofixOptions{RepoPath: t.TempDir(), FileID: 1},
		deps("app/A.java", fixResult{}))
	require.ErrorContains(t, err, "needs a Mycroft job")
}

func TestRunAutofix_KnoxIQCompleted_Continues(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	checked := 0
	d := deps(rel, fixResult{Changed: true, PatchedContent: "patched\n"})
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

func TestRunAutofix_RequiresToken(t *testing.T) {
	prev := viper.GetString("access-token")
	t.Cleanup(func() { viper.Set("access-token", prev) })
	viper.Set("access-token", "")
	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), FileID: 1, Units: jobUnits("x")}, deps("", fixResult{}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "APPKNOX_ACCESS_TOKEN")
}

func TestRunAutofix_RejectsPlaintextRemoteAPIHost(t *testing.T) {
	withAccessToken(t)
	prev := viper.GetString("host")
	t.Cleanup(func() { viper.Set("host", prev) })
	viper.Set("host", "http://remote.example.com")

	_, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), FileID: 1, Units: jobUnits("x")},
		deps("app/A.java", fixResult{}))
	require.Error(t, err)
}

func TestRunAutofix_Advisory_WhenLocateAbstains(t *testing.T) {
	withAccessToken(t)
	out, err := runAutofix(context.Background(),
		AutofixOptions{RepoPath: t.TempDir(), FileID: 1, Units: jobUnits("x")},
		deps("", fixResult{}))
	require.NoError(t, err)
	require.Empty(t, out.Located)
}

func TestRunAutofix_FullFlow_PushesBranch(t *testing.T) {
	root, rel := repoWithFile(t, "int r = new Random().nextInt();\n")
	res := fixResult{Changed: true, PatchedContent: "int r = new SecureRandom().nextInt();\n"}
	out, err := runAutofix(context.Background(), appknoxOpts(t, root),
		deps(rel, res))
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
	d := deps("", fixResult{Changed: true, PatchedContent: "fixed\n"})
	d.locate = func(_ context.Context, unit FindingUnit) (agent.TargetReply, error) {
		return agent.TargetReply{Targets: []agent.Target{{Path: "app/A.java"}, {Path: "app/B.java"}}}, nil
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
	d := deps("", fixResult{Changed: true, PatchedContent: "fixed\n"})
	d.locate = func(_ context.Context, unit FindingUnit) (agent.TargetReply, error) {
		return agent.TargetReply{Targets: []agent.Target{{Path: "app/A.java"}, {Path: "app/B.java"}}}, nil
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
		deps(rel, fixResult{Changed: true, PatchedContent: "patched\n"}))
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
		deps(rel, fixResult{Changed: true, PatchedContent: "patched\n"}))
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
	d := deps(rel, fixResult{Changed: true, PatchedContent: "patched\n"})
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
	d := deps(rel, fixResult{Changed: true, PatchedContent: "patched\n"})
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

func TestRunAutofix_EmptyPatchNotApplied(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	out, err := runAutofix(context.Background(), appknoxOpts(t, root),
		deps(rel, fixResult{Changed: true, PatchedContent: ""}))
	require.NoError(t, err)
	require.Empty(t, out.Patches) // empty content is not a patch
	got, _ := os.ReadFile(filepath.Join(root, rel))
	require.Equal(t, "orig\n", string(got))
}

func TestRunAutofix_NoChange_LeavesFile(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	out, err := runAutofix(context.Background(), appknoxOpts(t, root),
		deps(rel, fixResult{Changed: false}))
	require.NoError(t, err)
	require.Empty(t, out.Patches)
	require.Equal(t, []string{rel}, out.Located)
}

func TestRunAutofix_FileID_SkipsFailedFinding(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app/A.java"), []byte("orig\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app/B.java"), []byte("orig\n"), 0o644))
	pathFor := map[string]string{"u-Bad": "app/A.java", "u-Good": "app/B.java"}
	d := deps("", fixResult{Changed: true, PatchedContent: "fixed\n"})
	d.locate = func(_ context.Context, unit FindingUnit) (agent.TargetReply, error) {
		return agent.TargetReply{Targets: []agent.Target{{Path: pathFor[unit.UnitID]}}}, nil
	}
	d.fix = func(_ context.Context, _ string, tc targetContext, _ *patchViolation) (fixResult, error) {
		if tc.UnitID == "u-Bad" {
			return fixResult{}, errors.New("model failed")
		}
		return fixResult{Changed: true, PatchedContent: "fixed\n"}, nil
	}
	opts := appknoxOpts(t, root)
	opts.Units = jobUnits("Bad", "Good")
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Len(t, out.Patches, 1)
	require.Equal(t, "app/B.java", out.Patches[0].Path)
	require.Contains(t, out.BranchURL, "/pull/")
}

func TestAwaitAutofix_NilClient(t *testing.T) {
	_, err := awaitAutofix(context.Background(), nil, AutofixOptions{FileID: 118})
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
	req, err := awaitAutofix(context.Background(), client, AutofixOptions{FileID: 118, Repo: "appknox/mfva", Ref: "master"})
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
			"id": 12, "file": 118, "project": 45, "status": "Processing", "units": []any{},
		})
	})
	req, err := awaitAutofix(context.Background(), client, AutofixOptions{FileID: 118, Repo: "appknox/mfva", Ref: "master"})
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
	mux.HandleFunc("/api/knoxiq/file/118/autofix/12", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		n++
		body := map[string]any{
			"id": 12, "file": 118, "project": 45, "status": "Pending",
		}
		if n >= 2 {
			body["status"] = "Processing"
			body["units"] = []any{}
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	client := testAppknoxClient(t, mux.ServeHTTP)
	req, err := awaitAutofix(context.Background(), client, AutofixOptions{FileID: 118, Repo: "appknox/mfva", Ref: "master"})
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
	_, err := awaitAutofix(context.Background(), client, AutofixOptions{FileID: 118, Repo: "appknox/mfva", Ref: "master"})
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
	_, err := awaitAutofix(ctx, client, AutofixOptions{FileID: 118, Repo: "appknox/mfva", Ref: "master"})
	require.EqualError(t, err, "autofix timed out for file 118 after 1h0m0s")
	require.True(t, marked)
}

func TestAwaitAutofix_AlreadyTimedOut(t *testing.T) {
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 12, "file": 118, "project": 45, "status": "Timed Out",
		})
	})
	_, err := awaitAutofix(context.Background(), client, AutofixOptions{FileID: 118, Repo: "appknox/mfva", Ref: "master"})
	require.EqualError(t, err, "autofix timed out for file 118 after 1h0m0s")
}

func TestAwaitAutofix_StartError(t *testing.T) {
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "denied"})
	})
	_, err := awaitAutofix(context.Background(), client, AutofixOptions{FileID: 118, Repo: "appknox/mfva", Ref: "master"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "autofix start failed")
}

func TestPrAction(t *testing.T) {
	require.Equal(t, "Created PR", prAction(true))
	require.Equal(t, "Updated PR", prAction(false))
}

func TestProcessAutofix_AutofixBaseBranchPrintsAndReturns(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	prev := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = prev })

	ProcessAutofix(AutofixOptions{Ref: "appknox-autofix/feat/login"})

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Contains(t, string(out), "Autofix can not be run at appknox autofix branch")
}

// I3: a locate or fix call hitting the gateway's exhausted per-session budget
// must stop the run, keep the patches already produced, set Truncated, and
// (critically) not fail the run -- err is nil so ProcessAutofix exits 0.
func TestRunAutofix_FixBudgetExhausted_TruncatesButKeepsEarlierPatches(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	for _, rel := range []string{"app/A.java", "app/B.java", "app/C.java"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte("orig\n"), 0o644))
	}
	pathFor := map[string]string{"u-finding-1": "app/A.java", "u-finding-2": "app/B.java", "u-finding-3": "app/C.java"}
	d := deps("", fixResult{})
	d.locate = func(_ context.Context, unit FindingUnit) (agent.TargetReply, error) {
		return agent.TargetReply{Targets: []agent.Target{{Path: pathFor[unit.UnitID]}}}, nil
	}
	var attempted []string
	d.fix = func(_ context.Context, _ string, tc targetContext, _ *patchViolation) (fixResult, error) {
		attempted = append(attempted, tc.UnitID)
		if tc.UnitID == "u-finding-2" {
			return fixResult{}, errors.New("429 session call budget exhausted")
		}
		return fixResult{Changed: true, PatchedContent: "fixed\n"}, nil
	}
	opts := appknoxOpts(t, root)
	opts.Units = jobUnits("finding-1", "finding-2", "finding-3")
	opts.DryRun = true // no deliver stub needed; the assertions are about Outcome
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err, "a truncated run with patches already produced must not fail")
	require.NotEmpty(t, out.Truncated, "Truncated must be set")
	require.Len(t, out.Patches, 1, "only the target attempted before the exhaustion produced a patch")
	require.Equal(t, "app/A.java", out.Patches[0].Path)
	require.Equal(t, []string{"u-finding-1", "u-finding-2"}, attempted,
		"the exhausted target is attempted once, then no further targets are attempted")
}

// I3 (locate side): the same guard on the locate call, not just the fix call.
func TestRunAutofix_LocateBudgetExhausted_Truncates(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	d := deps(rel, fixResult{Changed: true, PatchedContent: "fixed\n"})
	var locateCalls int
	d.locate = func(context.Context, FindingUnit) (agent.TargetReply, error) {
		locateCalls++
		if locateCalls == 1 {
			return agent.TargetReply{Targets: []agent.Target{{Path: rel}}}, nil
		}
		return agent.TargetReply{}, errors.New("403 invalid credential")
	}
	opts := appknoxOpts(t, root)
	opts.Units = jobUnits("finding-1", "finding-2")
	opts.DryRun = true
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.NotEmpty(t, out.Truncated)
	require.Len(t, out.Patches, 1, "the patch located before the exhaustion is kept")
	require.Equal(t, 2, locateCalls, "the loop stops right after the exhausted locate call")
}

// I4: two findings that both patch the same file must both be named in the
// collapsed patch, and its diff must cover both edits -- not just the last.
func TestRunAutofix_TwoFindingsSameFile_CollapsedPatchNamesBothAndDiffsBoth(t *testing.T) {
	root, rel := repoWithFile(t, "line1\nline2\n")
	d := autofixDeps{
		locate: targetsAt(rel),
		fix: func(_ context.Context, _ string, tc targetContext, _ *patchViolation) (fixResult, error) {
			if tc.UnitID == "u-Finding A" {
				return fixResult{Changed: true, PatchedContent: "line1-fixedA\nline2\n"}, nil
			}
			return fixResult{Changed: true, PatchedContent: "line1-fixedA\nline2-fixedB\n"}, nil
		},
	}
	opts := appknoxOpts(t, root)
	opts.Units = jobUnits("Finding A", "Finding B")
	opts.DryRun = true
	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Len(t, out.Patches, 1, "one file, one collapsed patch")
	p := out.Patches[0]
	require.Contains(t, p.Finding, "Finding A")
	require.Contains(t, p.Finding, "Finding B")
	require.Contains(t, p.Diff, "fixedA", "the diff must show the FIRST finding's edit too")
	require.Contains(t, p.Diff, "fixedB", "the diff must show the second finding's edit")
	require.Equal(t, "line1-fixedA\nline2-fixedB\n", p.Content, "content is unaffected by this fix")
}

// M3: produceFixFor must read the pre-patch original through readUnderRoot --
// the same path-guard every other read in this package uses -- not a bare
// os.ReadFile(filepath.Join(root, path)), which a maliciously located path
// could use to escape the checkout root (CWE-22). This plants a real file
// OUTSIDE root that the old bare os.ReadFile(filepath.Join(...)) would have
// happily read; readUnderRoot's safeDest must refuse the escape instead, so
// verification is skipped (cannot be computed) rather than run against
// someone else's file.
func TestProduceFix_OriginalReadIsPathGuarded(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "checkout")
	require.NoError(t, os.MkdirAll(root, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("SECRET"), 0o644))

	s := fixSession{
		opts: AutofixOptions{},
		root: root,
		d: autofixDeps{
			fix: func(context.Context, string, targetContext, *patchViolation) (fixResult, error) {
				return fixResult{Changed: true, PatchedContent: "patched\n"}, nil
			},
		},
	}
	res, _, err := s.produceFixFor(context.Background(), "../secret.txt", targetContext{})
	require.NoError(t, err)
	require.Equal(t, "patched\n", res.PatchedContent,
		"the patch still ships because the original could not be read (safeDest refused the escape); "+
			"a bare os.ReadFile(filepath.Join(...)) would have read secret.txt instead")
}

// M2: runAutofix's unconditional defer restores the working tree; a failure
// there must be printed, never silently swallowed, and must NOT fail an
// otherwise successful run -- the fix is already delivered by the time the
// defer runs.
func TestRunAutofix_RestoreFailure_IsPrintedNotSwallowed(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	abs := filepath.Join(root, filepath.FromSlash(rel))
	d := deps(rel, fixResult{Changed: true, PatchedContent: "patched\n"})
	d.deliver = func(_ context.Context, _ AutofixOptions, patches []filePatch) (Delivery, error) {
		// Make the patched file unwritable so the unconditional restore in
		// runAutofix's defer -- which fires AFTER this stub returns -- fails.
		require.NoError(t, os.Chmod(abs, 0o444))
		t.Cleanup(func() { _ = os.Chmod(abs, 0o644) })
		return Delivery{URL: "https://github.com/appknox/mfva/pull/1"}, nil
	}
	opts := appknoxOpts(t, root)
	opts.Repo = "appknox/mfva"

	var out Outcome
	var err error
	output := captureOutput(func() {
		out, err = runAutofix(context.Background(), opts, d)
	})
	require.NoError(t, err, "a restore failure must not fail an otherwise successful run")
	require.Contains(t, out.BranchURL, "/pull/")
	require.Contains(t, output, "restore", "the restore failure must be printed, not swallowed")
}

func TestStampSeverity_TakesTheHighestRiskPerVulnerability(t *testing.T) {
	analyses := func(context.Context, int) ([]*appknox.Analysis, error) {
		return []*appknox.Analysis{
			{VulnerabilityID: 7, ComputedRisk: enums.Risk.Medium},
			{VulnerabilityID: 7, ComputedRisk: enums.Risk.High},
			{VulnerabilityID: 9, ComputedRisk: enums.Risk.Passed},
		}, nil
	}
	targets := []analysisTarget{
		{Inputs: FindingInputs{VulnerabilityID: 7, Skipped: []findingOutcome{{}}}},
		{Inputs: FindingInputs{VulnerabilityID: 9}},
	}
	stampSeverity(context.Background(), analyses, 1, targets)
	require.Equal(t, "High", targets[0].Inputs.Severity)
	require.Equal(t, "High", targets[0].Inputs.Skipped[0].Severity)
	require.Empty(t, targets[1].Inputs.Severity, "Passed is not a severity")
}

func TestStampSeverity_WithoutALookupLeavesSeverityEmpty(t *testing.T) {
	targets := []analysisTarget{{Inputs: FindingInputs{VulnerabilityID: 7}}}
	stampSeverity(context.Background(), nil, 1, targets)
	require.Empty(t, targets[0].Inputs.Severity)
}
