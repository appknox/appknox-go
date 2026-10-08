package helper

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/workspace"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

const (
	mainRel  = "app/src/main/java/com/appknox/mfva/MainActivity.java"
	mainBody = "package com.appknox.mfva;\nclass MainActivity { int r = new Random().nextInt(); }\n"
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

func TestPrAction(t *testing.T) {
	require.Equal(t, "Created PR", prAction(true))
	require.Equal(t, "Updated PR", prAction(false))
}

func TestValidateAPIEndpoint(t *testing.T) {
	require.NoError(t, validateAPIEndpoint("https://api.appknox.com"))
	require.NoError(t, validateAPIEndpoint("http://localhost:8000"))
	require.NoError(t, validateAPIEndpoint("http://127.0.0.1:8000"))
	require.Error(t, validateAPIEndpoint("http://api.appknox.com"))
}

func TestCallSummary_NamesCallsWithoutArguments(t *testing.T) {
	got := callSummary([]appknox.AutofixToolCall{
		{Name: "read_file", Args: map[string]interface{}{"path": "secret.java"}},
		{Name: "edit", Args: map[string]interface{}{"old_string": "md5"}},
		{Name: "read_file"},
	})
	require.Equal(t, "read_file×2, edit×1", got)
}

func targetPaths(ts []workspace.Target) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Path)
	}
	return out
}

// writeSource puts content on disk under root.
func writeSource(t *testing.T, root, rel, content string) {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o755))
	require.NoError(t, os.WriteFile(abs, []byte(content), 0o644))
}

// applyTracked writes content the way a session does: tracked, then written.
func applyTracked(t *testing.T, w *workingTree, path, content string) {
	t.Helper()
	require.NoError(t, w.track(path))
	require.NoError(t, applyPatch(w.root, path, content))
}

// A run must leave the checkout exactly as it found it.
func TestWorkingTree_RestoreUndoesEveryEdit(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/A.java": "original\n"})
	w := newWorkingTree(root)
	applyTracked(t, w, "app/A.java", "patched once\n")
	applyTracked(t, w, "app/A.java", "patched twice\n")
	require.NoError(t, w.restore())
	got, err := readUnderRoot(root, "app/A.java")
	require.NoError(t, err)
	require.Equal(t, "original\n", got)
}

// call runs one tool call and fails the test on an error result.
func call(t *testing.T, s *autofixSession, name string, args map[string]interface{}) appknox.AutofixToolResult {
	t.Helper()
	res := s.runAll([]appknox.AutofixToolCall{{ID: "c", Name: name, Args: args}})[0]
	require.False(t, res.IsError, "%s failed: %s", name, res.Content)
	return res
}

// asJSON round-trips data the way it travels to Appknox and back.
func asJSON(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func validate(t *testing.T, s *autofixSession, targets ...map[string]interface{}) map[string]interface{} {
	t.Helper()
	list := make([]interface{}, len(targets))
	for i, target := range targets {
		list[i] = target
	}
	return asJSON(t, call(t, s, toolValidateTargets, map[string]interface{}{
		"unit_id": "a1-F-0", "targets": list, "new_files": []interface{}{},
		"not_found": []interface{}{"okhttp3.Foo: library"}, "needs_new_file": []interface{}{},
	}).Data)
}

func TestSession_ReadToolsAnswerFromTheCheckout(t *testing.T) {
	s := newAutofixSession(writeRepo(t, map[string]string{mainRel: mainBody}))
	require.Contains(t, call(t, s, toolReadFile, map[string]interface{}{"path": mainRel}).Content, "new Random()")
	require.Contains(t, call(t, s, toolGrep, map[string]interface{}{"pattern": `new Random\(`}).Content, mainRel)
	require.Contains(t, call(t, s, toolGlob, map[string]interface{}{"pattern": "*MainActivity*"}).Content, mainRel)
	require.Contains(t, asJSON(t, call(t, s, toolProjectProfile, nil).Data), "profile")

	res := s.runAll([]appknox.AutofixToolCall{{ID: "x", Name: "shell"}})[0]
	require.True(t, res.IsError)
}

func TestSession_EditNeedsAnOpenTarget(t *testing.T) {
	s := newAutofixSession(writeRepo(t, map[string]string{mainRel: mainBody}))
	res := s.runAll([]appknox.AutofixToolCall{{ID: "e", Name: toolEdit, Args: map[string]interface{}{
		"path": mainRel, "old_string": "new Random()", "new_string": "new SecureRandom()"}}})[0]
	require.True(t, res.IsError)
	got, _ := readUnderRoot(s.root, mainRel)
	require.Equal(t, mainBody, got)
}

func TestSession_ValidateAcceptsExistingTargetsAndRefusesTheRest(t *testing.T) {
	s := newAutofixSession(writeRepo(t, map[string]string{mainRel: mainBody}))
	data := validate(t, s,
		map[string]interface{}{"path": mainRel, "why": "uses Random"},
		map[string]interface{}{"path": "../outside.java", "why": "x"},
	)
	require.Nil(t, data["skip"])
	accepted := data["accepted"].([]interface{})
	require.Len(t, accepted, 1)
	require.Equal(t, mainRel, accepted[0].(map[string]interface{})["path"])
	require.Len(t, data["results"], 1)
	require.Equal(t, []interface{}{"not found in repo: okhttp3.Foo: library"}, data["notes"])
}

func TestSession_ThirdPartyWithNoSourceIsSkipped(t *testing.T) {
	s := newAutofixSession(t.TempDir())
	data := asJSON(t, call(t, s, toolValidateTargets, map[string]interface{}{
		"unit_id": "a1-F-0", "third_party": true, "targets": []interface{}{},
	}).Data)
	require.Equal(t, true, data["skip"])
	require.Contains(t, data["detail"], reasonThirdPartyNoSource)
}

func TestSession_AcceptedEditStaysAndIsAPatch(t *testing.T) {
	s := newAutofixSession(writeRepo(t, map[string]string{mainRel: mainBody}))
	validate(t, s, map[string]interface{}{"path": mainRel, "why": "uses Random"})
	call(t, s, toolBeginTarget, map[string]interface{}{"path": mainRel, "new": false})
	call(t, s, toolEdit, map[string]interface{}{"path": mainRel,
		"old_string": "new Random()", "new_string": "new java.security.SecureRandom()"})

	data := asJSON(t, call(t, s, toolVerifyTarget, map[string]interface{}{"path": mainRel}).Data)
	require.Equal(t, true, data["accepted"])
	got, _ := readUnderRoot(s.root, mainRel)
	require.Contains(t, got, "SecureRandom")

	patches := s.result()
	require.Len(t, patches, 1)
	require.Equal(t, mainRel, patches[0].Path)
	require.Contains(t, patches[0].Diff, "+class MainActivity { int r = new java.security.SecureRandom()")
	require.NoError(t, s.work.restore())
	got, _ = readUnderRoot(s.root, mainRel)
	require.Equal(t, mainBody, got, "the checkout is put back after the run")
}

func TestSession_GateRefusalPutsTheFileBack(t *testing.T) {
	s := newAutofixSession(writeRepo(t, map[string]string{mainRel: mainBody}))
	validate(t, s, map[string]interface{}{"path": mainRel})
	call(t, s, toolBeginTarget, map[string]interface{}{"path": mainRel})
	call(t, s, toolEdit, map[string]interface{}{"path": mainRel,
		"old_string": "nextInt(); }", "new_string": "nextInt(); { }"})

	data := asJSON(t, call(t, s, toolVerifyTarget, map[string]interface{}{"path": mainRel}).Data)
	require.Equal(t, false, data["accepted"])
	require.Equal(t, "unbalanced-braces", data["violation"].(map[string]interface{})["rule"])
	got, _ := readUnderRoot(s.root, mainRel)
	require.Equal(t, mainBody, got)
	require.Empty(t, s.result())
}

func TestSession_DiscardPutsTheFileBack(t *testing.T) {
	s := newAutofixSession(writeRepo(t, map[string]string{mainRel: mainBody}))
	validate(t, s, map[string]interface{}{"path": mainRel})
	call(t, s, toolBeginTarget, map[string]interface{}{"path": mainRel})
	call(t, s, toolEdit, map[string]interface{}{"path": mainRel, "old_string": "Random", "new_string": "Rand"})
	data := asJSON(t, call(t, s, toolVerifyTarget, map[string]interface{}{"path": mainRel, "discard": true}).Data)
	require.Equal(t, false, data["changed"])
	got, _ := readUnderRoot(s.root, mainRel)
	require.Equal(t, mainBody, got)
}

// A new file and the edit that uses it are one change: when the edit is
// refused, finish_unit removes the new file too.
func TestSession_NewFileRolledBackWhenItsUserIsRefused(t *testing.T) {
	s := newAutofixSession(writeRepo(t, map[string]string{manifestRel: manifestBody}))
	data := asJSON(t, call(t, s, toolValidateTargets, map[string]interface{}{
		"unit_id":   "a1-F-0",
		"targets":   []interface{}{map[string]interface{}{"path": manifestRel, "why": "reference it"}},
		"new_files": []interface{}{map[string]interface{}{"path": nscRel, "why": "cleartext off"}},
	}).Data)
	accepted := data["accepted"].([]interface{})
	require.Len(t, accepted, 2)

	call(t, s, toolBeginTarget, map[string]interface{}{"path": nscRel, "new": true})
	call(t, s, toolCreateFile, map[string]interface{}{"path": nscRel, "content": nscBody})
	verified := asJSON(t, call(t, s, toolVerifyTarget, map[string]interface{}{"path": nscRel, "new": true}).Data)
	require.Equal(t, true, verified["accepted"])
	require.FileExists(t, filepath.Join(s.root, nscRel))

	finished := asJSON(t, call(t, s, toolFinishUnit, map[string]interface{}{
		"unit_id": "a1-F-0",
		"results": []interface{}{
			map[string]interface{}{"path": nscRel, "patched": true, "new": true},
			map[string]interface{}{"path": manifestRel, "patched": false, "reason": "rejected by patch gate (malformed-xml)"},
		},
	}).Data)
	results := finished["results"].([]interface{})
	require.Equal(t, reasonRolledBack, results[0].(map[string]interface{})["reason"])
	_, err := os.Stat(filepath.Join(s.root, nscRel))
	require.True(t, os.IsNotExist(err))
	require.Empty(t, s.result())
}

// finish_unit in the same batch as the last verify takes that target's
// result from the verdict, or holds back when Appknox will retry it.
func TestSession_FinishAfterVerify(t *testing.T) {
	s := newAutofixSession(writeRepo(t, map[string]string{mainRel: mainBody}))
	validate(t, s, map[string]interface{}{"path": mainRel})
	broken := map[string]interface{}{"path": mainRel, "old_string": "nextInt(); }", "new_string": "nextInt(); { }"}
	finish := map[string]interface{}{"unit_id": "a1-F-0", "results": []interface{}{},
		"after_verify": true, "retry_allowed": true}

	call(t, s, toolBeginTarget, map[string]interface{}{"path": mainRel})
	call(t, s, toolEdit, broken)
	call(t, s, toolVerifyTarget, map[string]interface{}{"path": mainRel})
	require.Equal(t, true, asJSON(t, call(t, s, toolFinishUnit, finish).Data)["deferred"])
	require.NotNil(t, s.unit, "a deferred finish leaves the finding open")

	// The retry is refused too, and no retry is left: the finding finishes.
	call(t, s, toolBeginTarget, map[string]interface{}{"path": mainRel})
	call(t, s, toolEdit, broken)
	call(t, s, toolVerifyTarget, map[string]interface{}{"path": mainRel})
	finish["retry_allowed"] = false
	data := asJSON(t, call(t, s, toolFinishUnit, finish).Data)
	results := data["results"].([]interface{})
	require.Len(t, results, 1)
	require.Equal(t, "rejected by patch gate (unbalanced-braces)", results[0].(map[string]interface{})["reason"])
	require.Nil(t, s.unit)
}

func TestVerdictResult(t *testing.T) {
	require.True(t, verdictResult(&verdict{path: "a", accepted: true}, "").Patched)
	require.Equal(t, "rejected by patch gate (xml)", verdictResult(&verdict{rule: "xml", changed: true}, "").Reason)
	require.Equal(t, "rejected by patch gate (xml), then declined", verdictResult(&verdict{}, "xml").Reason)
	require.Equal(t, "declined: no edit made", verdictResult(&verdict{}, "").Reason)
}

func TestNextPollInterval_BacksOffToTheCap(t *testing.T) {
	d := autofixFastPoll
	for i := 0; i < 20; i++ {
		d = nextPollInterval(d)
	}
	require.Equal(t, autofixPollInterval, d)
	require.Greater(t, nextPollInterval(autofixFastPoll), autofixFastPoll)
}

func TestSession_BeginRefusesANewFileThatExists(t *testing.T) {
	s := newAutofixSession(writeRepo(t, map[string]string{nscRel: nscBody}))
	validate(t, s)
	res := s.runAll([]appknox.AutofixToolCall{{ID: "b", Name: toolBeginTarget,
		Args: map[string]interface{}{"path": nscRel, "new": true}}})[0]
	require.True(t, res.IsError)
	require.Contains(t, res.Content, "already exists")
}

// fakeMycroft serves one job that asks for a read and an edit, then is Ready.
type fakeMycroft struct {
	t         *testing.T
	polls     int
	submitted [][]appknox.AutofixToolResult
	start     appknox.AutofixStart
}

func (f *fakeMycroft) handler() http.HandlerFunc {
	mux := http.NewServeMux()
	job := func(status string, step int, calls []map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"id": 12, "file": 118, "status": status, "step": step,
			"tool_calls": calls, "outcomes": []interface{}{}, "pr": nil}
	}
	mux.HandleFunc("/api/knoxiq/file/118/autofix", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(f.t, json.NewDecoder(r.Body).Decode(&f.start))
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(job("Pending", 0, nil))
	})
	mux.HandleFunc("/api/knoxiq/file/118/autofix/12", func(w http.ResponseWriter, r *http.Request) {
		f.polls++
		switch len(f.submitted) {
		case 0:
			_ = json.NewEncoder(w).Encode(job("Awaiting CLI", 1, []map[string]interface{}{
				{"id": "op-1", "name": "validate_targets", "args": map[string]interface{}{
					"unit_id": "a1-F-0", "targets": []interface{}{map[string]interface{}{"path": mainRel}}}},
			}))
		case 1:
			_ = json.NewEncoder(w).Encode(job("Awaiting CLI", 2, []map[string]interface{}{
				{"id": "op-2", "name": "begin_target", "args": map[string]interface{}{"path": mainRel}},
				{"id": "t1", "name": "edit", "args": map[string]interface{}{"path": mainRel,
					"old_string": "new Random()", "new_string": "new java.security.SecureRandom()"}},
				{"id": "op-3", "name": "verify_target", "args": map[string]interface{}{"path": mainRel}},
			}))
		default:
			ready := job("Ready", 3, nil)
			ready["outcomes"] = []interface{}{map[string]interface{}{"unit_id": "a1-F-0", "status": "FIXED",
				"finding": "Weak PRNG", "detail": mainRel}}
			ready["pr"] = map[string]interface{}{"title": "Appknox autofix: 1 finding fixed", "body": "summary"}
			_ = json.NewEncoder(w).Encode(ready)
		}
	})
	mux.HandleFunc("/api/knoxiq/file/118/autofix/12/tool_results", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Step    int                         `json:"step"`
			Results []appknox.AutofixToolResult `json:"results"`
		}
		require.NoError(f.t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(f.t, len(f.submitted)+1, body.Step)
		f.submitted = append(f.submitted, body.Results)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"detail":"Accepted."}`))
	})
	return mux.ServeHTTP
}

func autofixTestEnv(t *testing.T) {
	t.Helper()
	clearCIRepoEnv(t)
	prevToken, prevHost := viper.GetString("access-token"), viper.GetString("host")
	viper.Set("access-token", "tok")
	viper.Set("host", "https://api.appknox.test")
	t.Cleanup(func() {
		viper.Set("access-token", prevToken)
		viper.Set("host", prevHost)
	})
	prevSleep := autofixSleep
	autofixSleep = func(time.Duration) {}
	t.Cleanup(func() { autofixSleep = prevSleep })
}

func TestRunAutofix_AnswersToolCallsThenDeliversThePR(t *testing.T) {
	autofixTestEnv(t)
	root := writeRepo(t, map[string]string{mainRel: mainBody})
	fake := &fakeMycroft{t: t}
	var delivered []filePatch
	var prText *appknox.AutofixPRText
	reportedJob := 0
	d := autofixDeps{
		client:   testAppknoxClient(t, fake.handler()),
		baseTree: func(context.Context, AutofixOptions) (string, func(), error) { return root, func() {}, nil },
		deliver: func(_ context.Context, _ AutofixOptions, p []filePatch, pr *appknox.AutofixPRText) (Delivery, error) {
			delivered, prText = p, pr
			return Delivery{URL: "https://github.com/appknox/mfva/pull/7", PRCreated: true}, nil
		},
		report: func(_ context.Context, _ AutofixOptions, id int, _ Delivery, _ []filePatch) error {
			reportedJob = id
			return nil
		},
	}
	out, err := runAutofix(context.Background(), AutofixOptions{
		FileID: 118, Repo: "appknox/mfva", Ref: "main", HeadRef: "feat/login", RiskThreshold: 3,
	}, d)
	require.NoError(t, err)

	require.Equal(t, "main", fake.start.BaseRef)
	require.Equal(t, 3, fake.start.RiskThreshold)
	require.Len(t, fake.submitted, 2)
	require.Equal(t, mainRel, fake.submitted[0][0].Data["accepted"].([]interface{})[0].(map[string]interface{})["path"])
	verify := fake.submitted[1][2]
	require.Equal(t, "op-3", verify.ID)
	require.Equal(t, true, verify.Data["accepted"])

	require.Len(t, delivered, 1)
	require.Contains(t, delivered[0].Content, "SecureRandom")
	require.Equal(t, "Appknox autofix: 1 finding fixed", prText.Title)
	require.Equal(t, 12, reportedJob)
	require.Equal(t, "https://github.com/appknox/mfva/pull/7", out.BranchURL)
	require.Equal(t, "FIXED", out.Findings[0].Status)

	got, _ := readUnderRoot(root, mainRel)
	require.Equal(t, mainBody, got, "the checkout is restored after delivery")
}

func TestRunAutofix_NothingToDeliverWhenProcessed(t *testing.T) {
	autofixTestEnv(t)
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": 12, "status": "Processed",
			"outcomes": []interface{}{map[string]interface{}{"status": "SKIPPED", "detail": "KnoxIQ: no findings"}}})
	})
	d := autofixDeps{
		client:   client,
		baseTree: func(context.Context, AutofixOptions) (string, func(), error) { return t.TempDir(), func() {}, nil },
		deliver: func(context.Context, AutofixOptions, []filePatch, *appknox.AutofixPRText) (Delivery, error) {
			t.Fatal("nothing to deliver")
			return Delivery{}, nil
		},
	}
	out, err := runAutofix(context.Background(), AutofixOptions{FileID: 118, Repo: "o/r", Ref: "main"}, d)
	require.NoError(t, err)
	require.Equal(t, "SKIPPED", out.Findings[0].Status)
}

func TestRunAutofix_ErroredJobFails(t *testing.T) {
	autofixTestEnv(t)
	client := testAppknoxClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": 12, "status": "Errored",
			"error_message": "Sherrinford returned 502"})
	})
	d := autofixDeps{client: client,
		baseTree: func(context.Context, AutofixOptions) (string, func(), error) { return t.TempDir(), func() {}, nil }}
	_, err := runAutofix(context.Background(), AutofixOptions{FileID: 118, Repo: "o/r", Ref: "main"}, d)
	require.ErrorContains(t, err, "Sherrinford returned 502")
}

func TestRunAutofix_DeadlineMarksTheJobTimedOut(t *testing.T) {
	autofixTestEnv(t)
	marked := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/knoxiq/file/118/autofix", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": 12, "status": "Pending"})
	})
	mux.HandleFunc("/api/knoxiq/file/118/autofix/12/timeout", func(w http.ResponseWriter, r *http.Request) {
		marked = true
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": 12, "status": "Timed Out"})
	})
	client := testAppknoxClient(t, mux.ServeHTTP)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runJob(ctx, client, AutofixOptions{FileID: 118, Repo: "o/r", Ref: "main"}, newAutofixSession(t.TempDir()))
	require.Error(t, err)
	require.True(t, marked)
}

func TestRunAutofix_RequiresFileIDAndToken(t *testing.T) {
	autofixTestEnv(t)
	_, err := runAutofix(context.Background(), AutofixOptions{}, autofixDeps{})
	require.ErrorContains(t, err, "--file-id")

	viper.Set("access-token", "")
	_, err = runAutofix(context.Background(), AutofixOptions{FileID: 1}, autofixDeps{})
	require.ErrorContains(t, err, "access token")
}

func TestRunAutofix_RejectsPlaintextRemoteAPIHost(t *testing.T) {
	autofixTestEnv(t)
	viper.Set("host", "http://api.appknox.test")
	_, err := runAutofix(context.Background(), AutofixOptions{FileID: 1},
		autofixDeps{client: testAppknoxClient(t, func(http.ResponseWriter, *http.Request) {})})
	require.ErrorContains(t, err, "plaintext")
}

func TestResolveBaseTree_PushRunUsesTheCheckout(t *testing.T) {
	dir := t.TempDir()
	root, cleanup, err := resolveBaseTree(context.Background(),
		AutofixOptions{RepoPath: dir, Ref: "main", HeadRef: "main"})
	require.NoError(t, err)
	require.Equal(t, dir, root)
	cleanup()
	require.DirExists(t, dir)
}
