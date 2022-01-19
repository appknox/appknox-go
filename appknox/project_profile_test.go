package appknox

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestRegulatoryPreference_marshall(t *testing.T) {
	testJSONMarshal(t, &RegulatoryPreference{}, "{}")

	u := &RegulatoryPreference{Value: true}
	want := `{"value": true}`
	testJSONMarshal(t, u, want)
}
func TestProjectProfileReportPreference_marshall(t *testing.T) {
	testJSONMarshal(t, &ProjectProfileReportPreference{},
		`{"show_pcidss":{}, "show_hipaa":{}, "show_gdpr":{}}`)

	u := &ProjectProfileReportPreference{
		ShowPcidss: RegulatoryPreference{Value: true},
		ShowHipaa:  RegulatoryPreference{Value: true},
		ShowGdpr:   RegulatoryPreference{Value: true},
	}
	want := `{
		"show_pcidss": {"value": true},
		"show_hipaa": {"value": true},
		"show_gdpr": {"value": true}
	}`
	testJSONMarshal(t, u, want)
}

func TestProjectProfilesService_GetProjectProfileReportPreference(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v2/files/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":1, "profile": 1}`)
	})
	mux.HandleFunc("/api/profiles/1/report_preference", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{
			"show_pcidss": {"value": true},
			"show_hipaa": {"value": true},
			"show_gdpr": {"value": false}
		}`)
	})

	profileReportPreference, _, err := client.ProjectProfiles.GetProjectProfileReportPreference(context.Background(), 1)
	if err != nil {
		t.Errorf("ProjectProfiles.GetProjectProfileReportPreference return error: %v", err)
	}

	want := &ProjectProfileReportPreference{
		ShowPcidss: RegulatoryPreference{Value: true},
		ShowHipaa:  RegulatoryPreference{Value: true},
		ShowGdpr:   RegulatoryPreference{Value: false},
	}
	if !reflect.DeepEqual(profileReportPreference, want) {
		t.Errorf("ProjectProfiles.GetProjectProfileReportPreference returned %+v, want %+v",
			profileReportPreference, want)
	}
}

func TestProjectProfilesService_GetProjectProfileReportPreference_InvalidFileID(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v2/files/500", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"detail":"Not found."}`)
	})

	_, resp, err := client.ProjectProfiles.GetProjectProfileReportPreference(context.Background(), 500)
	if resp != nil {
		t.Errorf("ProjectProfile Report Preference should be nil for invalid file ID")
	}
	if !strings.Contains(err.Error(), "404 Not found") {
		t.Errorf("Error message is incorrect for invalid file ID")
	}
}

func TestProjectProfilesService_GetProjectProfileReportPreference_InvalidProfileID(t *testing.T) {
	// This situation is virtually impossible but let's test it anyway
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v2/files/500", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":1, "profile": 500}`)
	})
	mux.HandleFunc("/api/profiles/500/report_preference", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"detail":"Not found."}`)
	})

	_, resp, err := client.ProjectProfiles.GetProjectProfileReportPreference(context.Background(), 500)
	if resp != nil {
		t.Errorf("ProjectProfile Report Preference should be nil for invalid profile ID")
	}
	if !strings.Contains(err.Error(), "404 Not found") {
		t.Errorf("Error message is incorrect for invalid profile ID")
	}
}
