package appknox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/appknox/appknox-go/appknox/enums"
)

func TestKnoxIQFileScanStatus_Completed(t *testing.T) {
	cases := []struct {
		sast, dast int
		want       bool
	}{
		{KnoxIQScanStatusCompleted, KnoxIQScanStatusDisabled, true},
		{KnoxIQScanStatusCompleted, KnoxIQScanStatusRunning, true},
		{KnoxIQScanStatusDisabled, KnoxIQScanStatusCompleted, true},
		{KnoxIQScanStatusPending, KnoxIQScanStatusDisabled, false},
		{KnoxIQScanStatusRunning, KnoxIQScanStatusCompleted, false},
		{KnoxIQScanStatusNotTriggered, KnoxIQScanStatusDisabled, false},
		{KnoxIQScanStatusErrored, KnoxIQScanStatusDisabled, false},
		{KnoxIQScanStatusDisabled, KnoxIQScanStatusPending, false},
	}
	for _, tc := range cases {
		st := &KnoxIQFileScanStatus{SASTStatus: tc.sast, DASTStatus: tc.dast}
		if got := st.Completed(); got != tc.want {
			t.Errorf("sast=%d dast=%d Completed()=%v, want %v", tc.sast, tc.dast, got, tc.want)
		}
	}
	if (*KnoxIQFileScanStatus)(nil).Completed() {
		t.Error("nil status should not be completed")
	}
}

func TestKnoxIQService_GetScanStatus(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/file/375/knoxiq_scan/status", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":375,"sast_status":4,"dast_status":0}`)
	})

	got, _, err := client.KnoxIQ.GetScanStatus(context.Background(), 375)
	if err != nil {
		t.Fatalf("GetScanStatus returned error: %v", err)
	}
	if got.ID != 375 || got.SASTStatus != KnoxIQScanStatusCompleted || got.DASTStatus != KnoxIQScanStatusDisabled {
		t.Errorf("GetScanStatus returned %+v", got)
	}
	if !got.Completed() {
		t.Error("expected completed status")
	}
}

func TestKnoxIQ_ListCICDAnalyses(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/knoxiq/file/1/cicd_analyses", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count":1,"results":[{"id":1,"computed_risk":3,`+
			`"cvss_base":8.1,"vulnerability_id":9,"vulnerability_name":"SQLi",`+
			`"exploitability_score":7.5,"exploitability_likelihood":4,`+
			`"is_knoxiq_all_fp":false,"needs_review":false}]}`)
	})

	results, resp, err := client.KnoxIQ.ListCICDAnalyses(context.Background(), 1, nil)
	if err != nil {
		t.Errorf("KnoxIQ.ListCICDAnalyses returned error: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("count = %d, want 1", resp.Count)
	}
	if len(results) != 1 || results[0].VulnerabilityName != "SQLi" {
		t.Fatalf("results = %+v", results)
	}
	if results[0].ExploitabilityScore == nil || *results[0].ExploitabilityScore != 7.5 {
		t.Errorf("exploitability_score not parsed, got %+v", results[0].ExploitabilityScore)
	}
	if results[0].ExploitabilityLikelihood == nil ||
		*results[0].ExploitabilityLikelihood != enums.Exploitability.High {
		t.Errorf("exploitability_likelihood not parsed, got %+v", results[0].ExploitabilityLikelihood)
	}
}

func TestKnoxIQ_ListCICDAnalyses_404(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/knoxiq/file/1/cicd_analyses", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	_, _, err := client.KnoxIQ.ListCICDAnalyses(context.Background(), 1, nil)
	if err == nil {
		t.Errorf("KnoxIQ.ListCICDAnalyses expected a 404 error, got nil")
	}
}

func TestAutofixPR_marshall(t *testing.T) {
	testJSONMarshal(t, &AutofixPR{}, `{"repo":"","base_branch":"","branch":"","pr_url":""}`)
	u := &AutofixPR{
		ID:           1,
		File:         118,
		Repo:         "appknox/mfva",
		BaseBranch:   "master",
		Branch:       "appknox-autofix/analysis-118",
		PRURL:        "https://github.com/appknox/mfva/compare/master...b",
		CommitSHA:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PatchedFiles: []string{"app/src/Main.java"},
	}
	want := `{
		"id": 1,
		"file": 118,
		"repo": "appknox/mfva",
		"base_branch": "master",
		"branch": "appknox-autofix/analysis-118",
		"pr_url": "https://github.com/appknox/mfva/compare/master...b",
		"commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"patched_files": ["app/src/Main.java"]
	}`
	testJSONMarshal(t, u, want)
}

func TestKnoxIQService_CreateAutofixPR(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/file/118/autofix_prs", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		var got AutofixPR
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if got.CommitSHA != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
			t.Errorf("commit_sha = %q", got.CommitSHA)
		}
		if got.Branch != "appknox-autofix/analysis-118" {
			t.Errorf("branch = %q", got.Branch)
		}
		fmt.Fprint(w, `{"id":9,"file":118,"repo":"appknox/mfva","base_branch":"master","branch":"appknox-autofix/analysis-118","pr_url":"https://github.com/appknox/mfva/compare/master...b","commits":[{"id":3,"commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","patched_files":["app/src/Main.java"]}]}`)
	})

	in := &AutofixPR{
		Repo:         "appknox/mfva",
		BaseBranch:   "master",
		Branch:       "appknox-autofix/analysis-118",
		PRURL:        "https://github.com/appknox/mfva/compare/master...b",
		CommitSHA:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PatchedFiles: []string{"app/src/Main.java"},
	}
	got, _, err := client.KnoxIQ.CreateAutofixPR(context.Background(), 118, in)
	if err != nil {
		t.Fatalf("KnoxIQ.CreateAutofixPR returned error: %v", err)
	}
	if got.ID != 9 || got.File != 118 {
		t.Errorf("CreateAutofixPR returned %+v", got)
	}
	if len(got.Commits) != 1 || got.Commits[0].CommitSHA != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("CreateAutofixPR commits = %+v", got.Commits)
	}
}

func TestKnoxIQService_StartAutofix(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/file/118/autofix", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		var got AutofixStart
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if got.Repo != "appknox/mfva" || got.BaseRef != "main" || got.RiskThreshold != 2 {
			t.Errorf("start body = %+v", got)
		}
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"id":12,"file":118,"project":45,"status":"Pending","step":0,"tool_calls":[],"outcomes":[],"pr":null,"pr_url":null,"error_message":""}`)
	})

	got, _, err := client.KnoxIQ.StartAutofix(context.Background(), 118,
		&AutofixStart{Repo: "appknox/mfva", BaseRef: "main", HeadRef: "feat/x", RiskThreshold: 2})
	if err != nil {
		t.Fatalf("StartAutofix returned error: %v", err)
	}
	if got.ID != 12 || got.File != 118 || got.Project != 45 || got.Status != AutofixStatusPending {
		t.Errorf("StartAutofix returned %+v", got)
	}
}

func TestKnoxIQService_GetAutofixRequest(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/file/118/autofix/12", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":12,"file":118,"status":"Processing","step":3,`+
			`"units":[{"unit_id":"a1-F-0","vulnerability_id":null,"finding":"Weak hash","skip_reason":null}],"outcomes":[],"pr":null}`)
	})

	got, _, err := client.KnoxIQ.GetAutofixRequest(context.Background(), 118, 12)
	if err != nil {
		t.Fatalf("GetAutofixRequest returned error: %v", err)
	}
	if got.Status != AutofixStatusProcessing || got.Step != 3 || len(got.Units) != 1 {
		t.Fatalf("GetAutofixRequest returned %+v", got)
	}
	if got.Units[0].UnitID != "a1-F-0" || got.Units[0].VulnerabilityID != 0 || got.Units[0].SkipReason != "" {
		t.Errorf("unit = %+v", got.Units[0])
	}
}

func TestKnoxIQService_GetAutofixRequestBeforeUnitsAreBuilt(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/file/118/autofix/12", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":12,"status":"Pending","step":0,"units":null,"outcomes":[]}`)
	})
	got, _, err := client.KnoxIQ.GetAutofixRequest(context.Background(), 118, 12)
	if err != nil {
		t.Fatalf("GetAutofixRequest returned error: %v", err)
	}
	if got.Units != nil {
		t.Errorf("units before the worker built them = %+v, want nil", got.Units)
	}
}

func TestKnoxIQService_AutofixTurn(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/file/118/autofix/12/turn", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		var got map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		start := got["start"].(map[string]interface{})
		target := start["target"].(map[string]interface{})
		if got["unit_id"] != "a1-F-0" || start["kind"] != "fix" || target["path"] != "a.java" {
			t.Errorf("turn body = %+v", got)
		}
		if _, ok := got["tool_results"]; ok {
			t.Errorf("an opening call sends no tool_results: %+v", got)
		}
		fmt.Fprint(w, `{"type":"tool_calls","calls":[{"id":"t1","name":"read_file","args":{"path":"a.java"}}]}`)
	})

	got, _, err := client.KnoxIQ.AutofixTurn(context.Background(), 118, 12, &AutofixTurnRequest{
		UnitID: "a1-F-0",
		Start:  &AutofixTurnStart{Kind: AutofixTurnFix, Target: &AutofixFixTarget{Path: "a.java"}},
	})
	if err != nil {
		t.Fatalf("AutofixTurn returned error: %v", err)
	}
	if got.Type != AutofixTurnToolCalls || len(got.Calls) != 1 || got.Calls[0].Args["path"] != "a.java" {
		t.Errorf("AutofixTurn returned %+v", got)
	}
}

func TestKnoxIQService_CompleteAutofix(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/file/118/autofix/12/complete", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		var got AutofixComplete
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if len(got.Outcomes) != 1 || got.Outcomes[0].Status != "FIXED" || got.Outcomes[0].Files[0].Path != "a.java" {
			t.Errorf("complete body = %+v", got)
		}
		fmt.Fprint(w, `{"id":12,"status":"Ready","outcomes":[],"pr":{"title":"t","body":"b"}}`)
	})

	got, _, err := client.KnoxIQ.CompleteAutofix(context.Background(), 118, 12, []AutofixOutcome{
		{UnitID: "a1-F-0", Status: "FIXED", Files: []AutofixTargetOutcome{{Path: "a.java", Patched: true}}},
	})
	if err != nil {
		t.Fatalf("CompleteAutofix returned error: %v", err)
	}
	if got.Status != AutofixStatusReady || got.PR.Title != "t" {
		t.Errorf("CompleteAutofix returned %+v", got)
	}
}

func TestKnoxIQService_CompleteAutofixSendsAnEmptyList(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/file/118/autofix/12/complete", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.TrimSpace(string(raw)) != `{"outcomes":[]}` {
			t.Errorf("complete body = %s", raw)
		}
		fmt.Fprint(w, `{"id":12,"status":"Processed","outcomes":[],"pr":null}`)
	})
	if _, _, err := client.KnoxIQ.CompleteAutofix(context.Background(), 118, 12, nil); err != nil {
		t.Fatalf("CompleteAutofix returned error: %v", err)
	}
}

func TestKnoxIQService_MarkAutofixRequestTimedOut(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/file/118/autofix/12/timeout", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"id":12,"file":118,"status":"Timed Out"}`)
	})

	got, _, err := client.KnoxIQ.MarkAutofixRequestTimedOut(context.Background(), 118, 12)
	if err != nil {
		t.Fatalf("MarkAutofixRequestTimedOut returned error: %v", err)
	}
	if got.Status != AutofixStatusTimedOut {
		t.Errorf("MarkAutofixRequestTimedOut returned %+v", got)
	}
}
