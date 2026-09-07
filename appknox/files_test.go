package appknox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/appknox/appknox-go/appknox/enums"
)

func TestFiles_marshall(t *testing.T) {
	testJSONMarshal(t, &File{}, "{}")
	u := &File{
		ID:                 1,
		Name:               "file name",
		Version:            "1.0",
		VersionCode:        "1.0",
		DynamicStatus:      2,
		APIScanProgress:    1,
		IsStaticDone:       true,
		IsDynamicDone:      true,
		StaticScanProgress: 100,
		APIScanStatus:      2,
		Rating:             "4.5",
		IsManualDone:       true,
		IsAPIDone:          true,
		ProfileID:          1,
	}
	want := `{
		"id": 1,
		"name": "file name",
		"version": "1.0",
		"version_code": "1.0",
		"dynamic_status": 2,
		"api_scan_progress": 1,
		"is_static_done": true,
		"is_dynamic_done": true,
		"static_scan_progress": 100,
		"api_scan_status": 2,
		"rating": "4.5",
		"is_manual_done": true,
		"is_api_done": true,
		"profile": 1
	}`
	testJSONMarshal(t, u, want)
}

func TestFilesService_ListByProject(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/projects/1/files", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":1}]}`)
	})

	files, _, err := client.Files.ListByProject(context.Background(), 1, nil)

	if err != nil {
		t.Errorf("Files.ListByProject returned error: %v", err)
	}

	want := []*File{{ID: 1}}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("Files.ListByProject returned %+v, want %+v", files, want)
	}
}

func TestFileResponse_GetNext(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/projects/1/files", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "next": "next", "results":[{"id":1}]}`)
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":10}]}`)
	})
	_, fileResponse, err := client.Files.ListByProject(context.Background(), 1, nil)
	if err != nil {
		t.Errorf("Files.ListByProject returned error: %v", err)
	}
	files, _, err := fileResponse.GetNext()
	want := []*File{{ID: 10}}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("Files.ListByProject returned %+v, want %+v", files, want)
	}
}

func TestFileResponse_GetPrevious(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/projects/1/files", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "previous": "previous", "results":[{"id":10}]}`)
	})
	mux.HandleFunc("/previous", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results":[{"id":1}]}`)
	})
	_, fileResponse, err := client.Files.ListByProject(context.Background(), 1, nil)
	if err != nil {
		t.Errorf("Files.ListByProject returned error: %v", err)
	}
	files, _, err := fileResponse.GetPrevious()
	want := []*File{{ID: 1}}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("Projects.List returned %+v, want %+v", files, want)
	}
}

func TestFilesService_ListByProjectWithOptions(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/projects/1/files", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		testFormValues(t, r, values{
			"version_code": "3",
			"offset":       "1",
			"limit":        "1",
		})
		fmt.Fprint(w,
			`{"count":1, "results":[{"version_code":"3"}]}`)
	})
	options := &FileListOptions{
		VersionCode: "3",
		ListOptions: ListOptions{
			Offset: 1,
			Limit:  1},
	}
	files, _, err := client.Files.ListByProject(context.Background(), 1, options)
	if err != nil {
		t.Errorf("Files.ListByProject returned error: %v", err)
	}
	want := []*File{{VersionCode: "3"}}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("Files.ListByProject returned %+v, want %+v", files, want)
	}
}

func TestFilesService_GetByID(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v2/files/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id":1}`)
	})

	me, _, err := client.Files.GetByID(context.Background(), 1)
	if err != nil {
		t.Errorf("Files.GetByID returned error: %v", err)
	}

	want := &File{ID: 1}
	if !reflect.DeepEqual(me, want) {
		t.Errorf("Files.GetByID returned %+v, want %+v", me, want)
	}
}

func TestFilesService_GetScansStatusSummary(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v3/files/37/scans_status_summary", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{
			"is_manual_done": false,
			"is_static_done": true,
			"is_api_done": false,
			"is_dynamic_done": false,
			"static_scan_progress": 100,
			"api_scan_progress": 0,
			"dynamic_status": 0,
			"api_scan_status": -1,
			"manual_status": 0
		}`)
	})

	summary, _, err := client.Files.GetScansStatusSummary(context.Background(), 37)
	if err != nil {
		t.Errorf("Files.GetScansStatusSummary returned error: %v", err)
	}

	want := &ScanStatusSummary{
		IsManualDone:       false,
		IsStaticDone:       true,
		IsAPIDone:          false,
		IsDynamicDone:      false,
		StaticScanProgress: 100,
		APIScanProgress:    0,
		DynamicStatus:      0,
		APIScanStatus:      -1,
		ManualStatus:       0,
	}
	if !reflect.DeepEqual(summary, want) {
		t.Errorf("Files.GetScansStatusSummary returned %+v, want %+v", summary, want)
	}

	// 403 Forbidden test
	mux.HandleFunc("/api/v3/files/403/scans_status_summary", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"detail": "You do not have permission to perform this action."}`)
	})
	_, resp, err := client.Files.GetScansStatusSummary(context.Background(), 403)
	if err == nil {
		t.Errorf("Expected error for 403 Forbidden, got nil")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected response status 403, got %+v", resp)
	}

	// 404 Not Found test
	mux.HandleFunc("/api/v3/files/404/scans_status_summary", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"detail": "Not found."}`)
	})
	_, resp, err = client.Files.GetScansStatusSummary(context.Background(), 404)
	if err == nil {
		t.Errorf("Expected error for 404 Not Found, got nil")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected response status 404, got %+v", resp)
	}
}

func TestAutofixPR_marshall(t *testing.T) {
	testJSONMarshal(t, &AutofixPR{}, `{"analysis":0,"repo":"","base_branch":"","branch":"","pr_url":""}`)
	sourcePR := 15
	u := &AutofixPR{
		ID:           1,
		File:         118,
		Analysis:     11754,
		Repo:         "appknox/mfva",
		BaseBranch:   "master",
		Branch:       "appknox-autofix/analysis-11754",
		PRURL:        "https://github.com/appknox/mfva/compare/master...b",
		CommitSHA:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourcePR:     &sourcePR,
		PatchedFiles: []string{"app/src/Main.java"},
	}
	want := `{
		"id": 1,
		"file": 118,
		"analysis": 11754,
		"repo": "appknox/mfva",
		"base_branch": "master",
		"branch": "appknox-autofix/analysis-11754",
		"pr_url": "https://github.com/appknox/mfva/compare/master...b",
		"commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"source_pr": 15,
		"patched_files": ["app/src/Main.java"]
	}`
	testJSONMarshal(t, u, want)
}

func TestFilesService_CreateAutofixPR(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v2/files/118/autofix_prs", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		var got AutofixPR
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if got.Analysis != 11754 {
			t.Errorf("analysis = %d, want 11754", got.Analysis)
		}
		if got.CommitSHA != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
			t.Errorf("commit_sha = %q", got.CommitSHA)
		}
		fmt.Fprint(w, `{"id":9,"file":118,"analysis":11754,"repo":"appknox/mfva","base_branch":"master","branch":"appknox-autofix/analysis-11754","pr_url":"https://github.com/appknox/mfva/compare/master...b","commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","patched_files":["app/src/Main.java"]}`)
	})

	in := &AutofixPR{
		Analysis:     11754,
		Repo:         "appknox/mfva",
		BaseBranch:   "master",
		Branch:       "appknox-autofix/analysis-11754",
		PRURL:        "https://github.com/appknox/mfva/compare/master...b",
		CommitSHA:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PatchedFiles: []string{"app/src/Main.java"},
	}
	got, _, err := client.Files.CreateAutofixPR(context.Background(), 118, in)
	if err != nil {
		t.Fatalf("Files.CreateAutofixPR returned error: %v", err)
	}
	if got.ID != 9 || got.File != 118 || got.Analysis != 11754 {
		t.Errorf("CreateAutofixPR returned %+v", got)
	}
}

func TestFilesService_GetHealthScore(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/v3/files/37/health_score", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{
			"health_score": 85
		}`)
	})

	healthScore, _, err := client.Files.GetHealthScore(context.Background(), 37, nil)
	if err != nil {
		t.Errorf("Files.GetHealthScore returned error: %v", err)
	}

	want := &HealthScore{HealthScore: 85}
	if !reflect.DeepEqual(healthScore, want) {
		t.Errorf("Files.GetHealthScore returned %+v, want %+v", healthScore, want)
	}

	// Test with event_type parameter
	mux.HandleFunc("/api/v3/files/38/health_score", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		eventType := r.URL.Query().Get("event_type")
		if eventType != "sast_completed" {
			t.Errorf("Expected event_type=sast_completed, got %s", eventType)
		}
		fmt.Fprint(w, `{"health_score": 90}`)
	})
	options := &HealthScoreOptions{EventType: string(enums.EventTypeSASTCompleted)}
	healthScore, _, err = client.Files.GetHealthScore(context.Background(), 38, options)
	if err != nil {
		t.Errorf("Files.GetHealthScore with event_type returned error: %v", err)
	}
	want = &HealthScore{HealthScore: 90}
	if !reflect.DeepEqual(healthScore, want) {
		t.Errorf("Files.GetHealthScore with event_type returned %+v, want %+v", healthScore, want)
	}

	// 403 Forbidden test
	mux.HandleFunc("/api/v3/files/403/health_score", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"detail": "You do not have permission to perform this action."}`)
	})
	_, resp, err := client.Files.GetHealthScore(context.Background(), 403, nil)
	if err == nil {
		t.Errorf("Expected error for 403 Forbidden, got nil")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected response status 403, got %+v", resp)
	}

	// 404 Not Found test
	mux.HandleFunc("/api/v3/files/404/health_score", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"detail": "Not found."}`)
	})
	_, resp, err = client.Files.GetHealthScore(context.Background(), 404, nil)
	if err == nil {
		t.Errorf("Expected error for 404 Not Found, got nil")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected response status 404, got %+v", resp)
	}
}
