package appknox

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

func TestReportService_GetDownloadUrlCSV_Should_Return_URL(t *testing.T) {
	client, mux, _, teardown := setup()
	signedUrl := "http://example.com/signed/download/url/summarycsv"
	defer teardown()
	mux.HandleFunc("/api/v2/reports/1/summary_csv", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		respBody := fmt.Sprintf(`{"url": "%s"}`, signedUrl)
		fmt.Fprint(w, respBody)
	})
	url, err := client.Reports.GetDownloadUrlCSV(context.Background(), 1)
	if err != nil {
		t.Errorf("Reports.GetDownloadUrlCSV returned error %v", err)
	}
	if url != signedUrl {
		t.Errorf("Reports.GetDownloadUrlCSV returned incorrect url. Expected %s Got %s", signedUrl, url)
	}

}

func TestReportService_GetDownloadUrlCSV_Should_Throw_Error_For_404(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/reports/999/summary_csv", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"detail":"Not found."}`)
	})
	url, err := client.Reports.GetDownloadUrlCSV(context.Background(), 999)
	if url != "" {
		t.Errorf("Url should be empty for invalid report id")
	}
	if err.Error() != "Report with ID 999 doesn't exist. Are you sure 999 is a reportID?" {
		fmt.Println(err.Error())
		t.Errorf("Error message should be displayed for invalid reportID")
	}

}

func TestReportService_DownloadReportData_Should_Download_Data(t *testing.T) {
	client, mux, _, teardown := setup()
	signedUrl := "/signed/download/url/summarycsv"
	defer teardown()
	respBody := "reportData"
	mux.HandleFunc(signedUrl, func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, respBody)
	})
	reportData, err := client.Reports.DownloadReportData(context.Background(), signedUrl)
	body := string(reportData.Bytes())
	if body != respBody {
		t.Errorf("Reports.DownloadReportData failed. Expected %s, Got %s", respBody, body)

	}
	if err != nil {
		t.Errorf("Reports.DownloadReportData returned error: %v", err)
	}

}

func TestReportService_DownloadReportData_Should_Throw_Error_If_Not_200(t *testing.T) {
	client, mux, _, teardown := setup()
	signedUrl := "/signed/download/url/summarycsv"
	defer teardown()

	mux.HandleFunc(signedUrl, func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := client.Reports.DownloadReportData(context.Background(), signedUrl)
	if err.Error() != "We are facing issues while downloading the report." {
		t.Error("Reports.DownloadReportData should throw error message if download failed")
	}

}
