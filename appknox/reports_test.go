package appknox

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"testing"
)

func TestReportsService_GetReportURL(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/hudson-api/reports/1", func(w http.ResponseWriter, r *http.Request) {
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

func TestReportsService_DownloadFile(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept download request
	mux.HandleFunc("/aws_fake_signed_url.txt?signature=fake_signature_hash", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `Fake_File_Content`)
	})

	outputDir := ".."
	report, err := client.Reports.DownloadFile(context.Background(), client.BaseURL.Scheme+"://"+client.BaseURL.Host+"/aws_fake_signed_url.txt?signature=fake_signature_hash", outputDir)

	if err != nil {
		t.Errorf("Reports.DownloadFile returned error: %v", err)
	}

	want := "../aws_fake_signed_url.txt"
	if !reflect.DeepEqual(report, want) {
		t.Errorf("Reports.DownloadFile returned %+v, want %+v", report, want)
	}

	os.Remove(want)
}
