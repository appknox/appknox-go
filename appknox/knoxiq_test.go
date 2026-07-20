package appknox

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/appknox/appknox-go/appknox/enums"
)

func TestKnoxIQ_GetScanStatus(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/knoxiq/file/1/knoxiq_scan/status", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":1,"sast_status":4,"dast_status":0}`)
	})

	status, _, err := client.KnoxIQ.GetScanStatus(context.Background(), 1)
	if err != nil {
		t.Errorf("KnoxIQ.GetScanStatus returned error: %v", err)
	}
	if status.SastStatus != 4 || status.DastStatus != 0 {
		t.Errorf("KnoxIQ.GetScanStatus = %+v, want sast=4 dast=0", status)
	}
}

func TestKnoxIQ_ListCICDAnalyses(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/knoxiq/file/1/cicd/analyses", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/api/knoxiq/file/1/cicd/analyses", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	_, _, err := client.KnoxIQ.ListCICDAnalyses(context.Background(), 1, nil)
	if err == nil {
		t.Errorf("KnoxIQ.ListCICDAnalyses expected a 404 error, got nil")
	}
}
