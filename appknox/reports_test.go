package appknox

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestReportService_ListByFile(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"count": 1, "results": [{"id": 1}]}`)
	})

	reports, err := client.Reports.List(context.Background(), 1)
	if err != nil {
		t.Errorf("Reports.List returned error: %v", err)
	}
	want := []*ReportResult{{ID: 1}}
	if !reflect.DeepEqual(reports, want) {
		t.Errorf("Reports.List returned %+v, want %+v", reports, want)
	}

}

func TestReportService_InvalidFileID(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/files/999/reports", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"detail":"Not found."}`)
	})
	resp, err := client.Reports.List(context.Background(), 999)
	if resp != nil {
		t.Errorf("ReportREsult should be nil for invalid fileID")
	}
	if err.Error() != "Reports for fileID 999 doesn't exist. Are you sure 999 is a fileID?" {
		t.Errorf("Error message should be displayed for invalid fileID")
	}

}
