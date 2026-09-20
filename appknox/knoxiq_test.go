package appknox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"id":12,"file":118,"project":45,"status":"Pending","pr_url":null,"error_message":""}`)
	})

	got, _, err := client.KnoxIQ.StartAutofix(context.Background(), 118)
	if err != nil {
		t.Fatalf("StartAutofix returned error: %v", err)
	}
	if got.ID != 12 || got.File != 118 || got.Project != 45 || got.Status != AutofixStatusPending {
		t.Errorf("StartAutofix returned %+v", got)
	}
}

func TestKnoxIQService_GetAutofixStatus(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/file/118/autofix/status", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":12,"file":118,"project":45,"status":"Processed","pr_url":"https://github.com/appknox/mfva/pull/16","error_message":""}`)
	})

	got, _, err := client.KnoxIQ.GetAutofixStatus(context.Background(), 118)
	if err != nil {
		t.Fatalf("GetAutofixStatus returned error: %v", err)
	}
	if got.Status != AutofixStatusProcessed || got.PRURL != "https://github.com/appknox/mfva/pull/16" {
		t.Errorf("GetAutofixStatus returned %+v", got)
	}
	if got.Project != 45 || got.File != 118 {
		t.Errorf("GetAutofixStatus ids = %+v", got)
	}
}

func TestKnoxIQService_MarkAutofixTimedOut(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/file/118/autofix/timeout", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		fmt.Fprint(w, `{"id":12,"file":118,"project":45,"status":"Timed Out","pr_url":null,"error_message":""}`)
	})

	got, _, err := client.KnoxIQ.MarkAutofixTimedOut(context.Background(), 118)
	if err != nil {
		t.Fatalf("MarkAutofixTimedOut returned error: %v", err)
	}
	if got.Status != AutofixStatusTimedOut || got.File != 118 || got.Project != 45 {
		t.Errorf("MarkAutofixTimedOut returned %+v", got)
	}
}
