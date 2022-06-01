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

func TestReportsService_GetReportURL_Success(t *testing.T) {
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

func TestReportsService_GetReportURL_IFAPINotWorking_ShuldFail(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	// Starting fake server to accept request
	mux.HandleFunc("/api/hudson-api/reports/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := client.Reports.GetReportURL(context.Background(), 1)

	// Assert http response code
	assert.Equal(t, strings.TrimSpace(strings.Split(err.Error(), ":")[3]), "500")
}

func TestReportsService_DownloadFile(t *testing.T) {
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
