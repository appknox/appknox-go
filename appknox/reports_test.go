package appknox

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
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

func TestReportService_WriteReportDataToFile_Should_Save_Report_To_File(t *testing.T) {
	client, _, _, teardown := setup()
	defer teardown()
	reportContent := `
	column0, column1, column2
	data0, data1, data2
	`
	reportData := bytes.NewBufferString(reportContent)
	tempdir := t.TempDir()
	outputFilePath := filepath.Join(tempdir, "report.csv")
	filePath, err := client.Reports.WriteReportDataToFile(*reportData, outputFilePath)
	fileContentBytes, err := ioutil.ReadFile(filePath)
	if string(fileContentBytes) != reportContent {
		t.Errorf("Reports.WriteReportDataToFile failed to write exepcted report content to file")
	}
	if err != nil {
		t.Errorf("Reports.WriteReportDataToFile returned error %v", err)
	}

}

func TestReportService_WriteReportDataToFile_Should_Throw_Error_If_Filename_Is_Dir(t *testing.T) {
	client, _, _, teardown := setup()
	defer teardown()
	reportContent := `
	column0, column1, column2
	data0, data1, data2
	`
	reportData := bytes.NewBufferString(reportContent)
	tempdir := t.TempDir()
	outputFilePath := filepath.Join(tempdir, "/")
	filePath, err := client.Reports.WriteReportDataToFile(*reportData, outputFilePath)
	if filePath != "" {
		t.Errorf("Reports.WriteReportDataToFile should return empty filepath for error")
	}
	if err == nil {
		t.Errorf("Reports.WriteReportDataToFile should returned error details if directory is passed as file name")
	}

}
func TestReportService_WriteReportDataToFile_Should_Throw_Error_If_Filename_Is_Empty(t *testing.T) {
	client, _, _, teardown := setup()
	defer teardown()
	reportContent := `
	column0, column1, column2
	data0, data1, data2
	`
	reportData := bytes.NewBufferString(reportContent)
	filePath, err := client.Reports.WriteReportDataToFile(*reportData, "")
	fmt.Println(err)
	if filePath != "" {
		t.Errorf("Reports.WriteReportDataToFile should return empty filepath for error")
	}
	if err == nil {
		t.Errorf("Reports.WriteReportDataToFile should returned error details if directory is passed as file name")
	}

}
