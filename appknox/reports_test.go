package appknox

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/magiconair/properties/assert"
)

func TestReportsService_GenerateReport_Success(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		resp := fmt.Sprintf(`{
			"id": %d,
			"language": "en",
			"progress": 50,
			"rating": "20.73"
		}`, 1)
		fmt.Fprint(w, resp)
	})

	report, err := client.Reports.GenerateReport(context.Background(), 1)

	if err != nil {
		t.Errorf("Reports.GenerateReport returned error: %v", err)
	}

	want := &ReportResult{
		ID:       1,
		Language: "en",
		Progress: 50,
		Rating:   "20.73",
	}
	if !reflect.DeepEqual(report, want) {
		t.Errorf("Reports.GenerateReport returned %+v, want %+v", report, want)
	}
}

func TestReportsService_GenerateReport_IfAPIFails_Should_Fail(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusNotFound)
	})

	report, err := client.Reports.GenerateReport(context.Background(), 1)

	assert.Equal(t, true, err != nil)
	assert.Equal(t, true, report == nil)
}

func TestReportsService_GenerateReport_IfBaseURL_Should_Fail(t *testing.T) {
	client, _, _, teardown := setup()
	defer teardown()
	// Setting invalid schame name to fail in `client.NewRequest`
	client.BaseURL.Scheme = ""
	client.BaseURL.Host = "localhost/"

	report, err := client.Reports.GenerateReport(context.Background(), 1)

	assert.Equal(t, true, err != nil)
	assert.Equal(t, true, report == nil)
}

func TestReportsService_FetchReportResult_Success(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/reports/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		resp := fmt.Sprintf(`{
			"id": %d,
			"language": "en",
			"progress": 100,
			"rating": "20.73"
		}`, 1)
		fmt.Fprint(w, resp)
	})

	report, err := client.Reports.FetchReportResult(context.Background(), 1)

	if err != nil {
		t.Errorf("Reports.FetchReportResult returned error: %v", err)
	}

	want := &ReportResult{
		ID:       1,
		Language: "en",
		Progress: 100,
		Rating:   "20.73",
	}
	if !reflect.DeepEqual(report, want) {
		t.Errorf("Reports.FetchReportResult returned %+v, want %+v", report, want)
	}
}

func TestReportsService_FetchReportResult_IfAPIFails_Should_Fail(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/reports/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
	})

	report, err := client.Reports.FetchReportResult(context.Background(), 1)

	assert.Equal(t, true, err != nil)
	assert.Equal(t, true, report == nil)
}

func TestReportsService_FetchReportResult_IfBaseURL_Should_Fail(t *testing.T) {
	client, _, _, teardown := setup()
	defer teardown()
	// Setting invalid schame name to fail in `client.NewRequest`
	client.BaseURL.Scheme = ""
	client.BaseURL.Host = "localhost/"

	report, err := client.Reports.FetchReportResult(context.Background(), 1)

	assert.Equal(t, true, err != nil)
	assert.Equal(t, true, report == nil)
}

func TestReportsService_FetchLastReportResult_Success(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		resp := fmt.Sprintf(`{
			"count": 1,
			"next": null,
			"previous": null,
			"results": [
				{
					"id": %d,
					"language": "en",
					"progress": 100,
					"rating": "20.73"
				}
			]
		}`, 1)
		fmt.Fprint(w, resp)
	})

	report, err := client.Reports.FetchLastReportResult(context.Background(), 1)

	if err != nil {
		t.Errorf("Reports.FetchLastReportResult returned error: %v", err)
	}

	want := &ReportResult{
		ID:       1,
		Language: "en",
		Progress: 100,
		Rating:   "20.73",
	}

	if !reflect.DeepEqual(report, want) {
		t.Errorf("Reports.FetchLastReportResult returned %+v, want %+v", report, want)
	}
}

func TestReportsService_FetchLastReportResult_IfEmptyReport_Should_Fail(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		resp := fmt.Sprintf(`{
			"count": 1,
			"next": null,
			"previous": null,
			"results": []
		}`)
		fmt.Fprint(w, resp)
	})

	report, err := client.Reports.FetchLastReportResult(context.Background(), 1)

	assert.Equal(t, true, err != nil)
	assert.Equal(t, err.Error(), "No report results found")
	assert.Equal(t, true, report == nil)
}

func TestReportsService_FetchLastReportResult_IfAPIFails_Should_Fail(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
	})

	report, err := client.Reports.FetchLastReportResult(context.Background(), 1)

	assert.Equal(t, true, err != nil)
	assert.Equal(t, true, report == nil)
}

func TestReportsService_FetchLastReportResult_IfBaseURL_Should_Fail(t *testing.T) {
	client, _, _, teardown := setup()
	defer teardown()
	// Setting invalid schame name to fail in `client.NewRequest`
	client.BaseURL.Scheme = ""
	client.BaseURL.Host = "localhost/"

	report, err := client.Reports.FetchLastReportResult(context.Background(), 1)

	assert.Equal(t, true, err != nil)
	assert.Equal(t, true, report == nil)
}

func TestReportsService_GetReportURL_Success(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/reports/1/pdf", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"url":"http://example.com"}`)
	})

	report, err := client.Reports.GetReportURL(context.Background(), 1)

	if err != nil {
		t.Errorf("Reports.GetReportURL returned error: %v", err)
	}

	want := &Report{URL: "http://example.com"}
	if !reflect.DeepEqual(report, want) {
		t.Errorf("Reports.GetReportURL returned %+v, want %+v", report, want)
	}
}

func TestReportsService_GetReportURL_IFAPINotWorking_ShuldFail(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/reports/1/pdf", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := client.Reports.GetReportURL(context.Background(), 1)

	// Assert http response code
	assert.Equal(t, strings.TrimSpace(strings.Split(err.Error(), ":")[3]), "500")
}

func TestReportsService_GetReportURL_IFBaseURL_ShuldFail(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/v2/reports/1/pdf", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusInternalServerError)
	})

	// Setting invalid schame name to fail in `client.NewRequest`
	client.BaseURL.Scheme = ""
	client.BaseURL.Host = "localhost/"

	_, err := client.Reports.GetReportURL(context.Background(), 1)
	assert.Equal(t, true, err != nil)
}

func TestReportsService_DownloadFile_Success(t *testing.T) {
	client, mux, serverURL, teardown := setup()
	defer teardown()

	// Starting fake server to accept download request
	mux.HandleFunc("/aws_fake_signed_url.txt", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `Fake_File_Content`)
	})

	outputDir := ".."
	report, err := client.Reports.DownloadFile(context.Background(), serverURL+"/aws_fake_signed_url.txt?signature=fake_signature_hash", outputDir)

	if err != nil {
		t.Errorf("Reports.DownloadFile returned error: %v", err)
	}

	want := "../aws_fake_signed_url.txt"
	if !reflect.DeepEqual(report, want) {
		t.Errorf("Reports.DownloadFile returned %+v, want %+v", report, want)
	}

	// remove files after test
	err = os.Remove(want)
	assert.Equal(t, nil, err)
}

func TestReportsService_DownloadFile_IfWrongURL_Should_Fail(t *testing.T) {
	client, mux, serverURL, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/aws_fake_signed_url.txt", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
	})

	outputDir := ".."
	report, err := client.Reports.DownloadFile(context.Background(), serverURL+"/aws_fake_signed_url.txt?signature=fake_signature_hash", outputDir)
	assert.Equal(t, true, err != nil)
	assert.Equal(t, true, len(report) == 0)
}

func TestReportsService_DownloadFile_IfInvalidURL_Should_Fail(t *testing.T) {
	client, _, _, teardown := setup()
	defer teardown()

	outputDir := ".."
	report, err := client.Reports.DownloadFile(context.Background(), "", outputDir)
	assert.Equal(t, true, err != nil)
	assert.Equal(t, true, len(report) == 0)
}

func TestReportsService_DownloadFile_IfBaseURL_Should_Fail(t *testing.T) {
	client, _, _, teardown := setup()
	defer teardown()
	// Setting invalid schame name to fail in `client.NewRequest`
	client.BaseURL.Scheme = ""
	client.BaseURL.Host = "localhost/"

	outputDir := ".."
	report, err := client.Reports.DownloadFile(context.Background(), "", outputDir)
	assert.Equal(t, true, err != nil)
	assert.Equal(t, true, len(report) == 0)
}
