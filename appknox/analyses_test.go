package appknox

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestAnalyses_marshall(t *testing.T) {
	testJSONMarshal(t, &Analysis{}, "{}")
	u := &Analysis{
		ID:              1,
		Risk:            2,
		OverRiddenRisk:  1,
		ComputedRisk:    2,
		Status:          3,
		CvssVector:      "c",
		CvssBase:        1.01,
		CvssVersion:     1,
		VulnerabilityID: 1,
	}
	want := `{
		"id": 1,
		"risk": 2,
		"overridden_risk": 1,
		"computed_risk": 2,
		"status": 3,
		"cvss_vector": "c",
		"cvss_base": 1.01,
		"cvss_version": 1,
		"vulnerability": 1
	}`
	testJSONMarshal(t, u, want)
}

func TestAnalysesService_ListByFile(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v2/files/1/analyses", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":1}]}`)
	})

	analyses, _, err := client.Analyses.ListByFile(context.Background(), 1, nil)
	if err != nil {
		t.Errorf("Analyses.ListByFile returned error: %v", err)
	}

	want := []*Analysis{{ID: 1}}
	if !reflect.DeepEqual(analyses, want) {
		t.Errorf("Analyses.ListByFile returned %+v, want %+v", analyses, want)
	}
}
func TestAnalysesService_ListByFileWithOptions(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v2/files/1/analyses", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		testFormValues(t, r, values{
			"offset": "1",
			"limit":  "1",
		})
		fmt.Fprint(w, `{"count": 1, "results":[{"id":1}]}`)
	})

	options := &AnalysisListOptions{
		ListOptions: ListOptions{
			Offset: 1,
			Limit:  1},
	}
	analyses, _, err := client.Analyses.ListByFile(context.Background(), 1, options)

	if err != nil {
		t.Errorf("Analyses.ListByFile returned error: %v", err)
	}

	want := []*Analysis{{ID: 1}}
	if !reflect.DeepEqual(analyses, want) {
		t.Errorf("Analyses.ListByFile returned %+v, want %+v", analyses, want)
	}
}

func TestAnalysisResponse_GetNext(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v2/files/1/analyses", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "next": "next", "results":[{"id":1}]}`)
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":10}]}`)
	})
	_, aResponse, err := client.Analyses.ListByFile(context.Background(), 1, nil)
	if err != nil {
		t.Errorf("Analyses.ListByFile returned error: %v", err)
	}
	analyses, _, err := aResponse.GetNext()
	if err != nil {
		t.Errorf("Analyses.ListByFile returned error: %v", err)
	}
	want := []*Analysis{{ID: 10}}
	if !reflect.DeepEqual(analyses, want) {
		t.Errorf("Analyses.ListByFile returned %+v, want %+v", analyses, want)
	}
}

func TestAnalysisResponse_GetPrevious(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/files/1/analyses", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "previous": "previous", "results":[{"id":10}]}`)
	})
	mux.HandleFunc("/previous", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":1}]}`)
	})
	_, aResponse, err := client.Analyses.ListByFile(context.Background(), 1, nil)
	if err != nil {
		t.Errorf("Analyses.ListByFile returned error: %v", err)
	}
	analyses, _, err := aResponse.GetPrevious()
	if err != nil {
		t.Errorf("Analyses.ListByFile returned error: %v", err)
	}
	want := []*Analysis{{ID: 1}}
	if !reflect.DeepEqual(analyses, want) {
		t.Errorf("Analyses.ListByFile returned %+v, want %+v", analyses, want)
	}
}
