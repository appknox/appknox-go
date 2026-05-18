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
func TestReportService_GetDownloadUrlExcel_Should_Return_URL(t *testing.T) {
	client, mux, _, teardown := setup()
	signedUrl := "http://example.com/signed/download/url/summaryexcel"
	defer teardown()
	mux.HandleFunc("/api/v2/reports/1/summary_excel", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		respBody := fmt.Sprintf(`{"url": "%s"}`, signedUrl)
		fmt.Fprint(w, respBody)
	})
	url, err := client.Reports.GetDownloadUrlExcel(context.Background(), 1)
	if err != nil {
		t.Errorf("Reports.GetDownloadUrlCSV returned error %v", err)
	}
	if url != signedUrl {
		t.Errorf("Reports.GetDownloadUrlCSV returned incorrect url. Expected %s Got %s", signedUrl, url)
	}

}

func TestReportService_GetDownloadUrlExcel_Should_Throw_Error_For_404(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/reports/999/summary_excel", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"detail":"Not found."}`)
	})
	url, err := client.Reports.GetDownloadUrlExcel(context.Background(), 999)
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
func TestReportService_CreateReport_Should_Return_New_Report_ID(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		fmt.Fprintf(w, `{"id": 1, "file_id": 1, "progress": 0}`)
	})
	report, alreadyExists, err := client.Reports.CreateReport(context.Background(), 1)
	if report.ID != 1 {
		t.Errorf("Reports.CreateReport failed Expected reportID %d, Got %d", 1, report.ID)
	}
	if alreadyExists {
		t.Errorf("Reports.CreateReport should return alreadyExists=false for new report")
	}
	if err != nil {
		t.Errorf("Reports.CreateReport returned error: %v", err)
	}
}

func TestReportService_CreateReport_Should_Return_AlreadyExists_On_400(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"message": "Report can't be generated"}`)
	})
	report, alreadyExists, err := client.Reports.CreateReport(context.Background(), 1)
	if report != nil {
		t.Errorf("Reports.CreateReport should return nil report on 400")
	}
	if !alreadyExists {
		t.Errorf("Reports.CreateReport should return alreadyExists=true on 400")
	}
	if err != nil {
		t.Errorf("Reports.CreateReport should return nil error on 400 (alreadyExists handles it)")
	}
}

func TestReportService_CreateReport_Should_Return_Error_On_Server_Error(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"message": "Internal server error"}`)
	})
	report, alreadyExists, err := client.Reports.CreateReport(context.Background(), 1)
	if report != nil {
		t.Errorf("Reports.CreateReport should return nil report on server error")
	}
	if alreadyExists {
		t.Errorf("Reports.CreateReport should return alreadyExists=false on server error")
	}
	if err == nil {
		t.Errorf("Reports.CreateReport should return error on 500 response")
	}
}

func TestReportService_GetLatestReport_Should_Return_First_Report(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"results": [{"id": 7, "file_id": 1, "progress": 100}]}`)
	})
	report, err := client.Reports.GetLatestReport(context.Background(), 1)
	if err != nil {
		t.Errorf("Reports.GetLatestReport returned error %v", err)
	}
	if report.ID != 7 {
		t.Errorf("Reports.GetLatestReport returned incorrect ID. Expected 7, Got %d", report.ID)
	}
}

func TestReportService_GetLatestReport_Should_Return_Error_If_No_Reports(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/files/1/reports", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"results": []}`)
	})
	report, err := client.Reports.GetLatestReport(context.Background(), 1)
	if report != nil {
		t.Errorf("Reports.GetLatestReport should return nil when no reports exist")
	}
	if err == nil {
		t.Errorf("Reports.GetLatestReport should return error when no reports exist")
	}
}

func TestReportService_GetReport_Should_Return_Report_With_Progress(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/reports/1/", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"id": 1, "progress": 75, "rating": "A"}`)
	})
	report, err := client.Reports.GetReport(context.Background(), 1)
	if err != nil {
		t.Errorf("Reports.GetReport returned error %v", err)
	}
	if report.ID != 1 {
		t.Errorf("Reports.GetReport returned incorrect report ID. Expected 1, Got %d", report.ID)
	}
	if report.Progress != 75 {
		t.Errorf("Reports.GetReport returned incorrect progress. Expected 75, Got %d", report.Progress)
	}
}

func TestReportService_GetReport_Should_Throw_Error_For_404(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/reports/999/", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"detail":"Not found."}`)
	})
	report, err := client.Reports.GetReport(context.Background(), 999)
	if report != nil {
		t.Errorf("Report should be nil for invalid report id")
	}
	if err.Error() != "Report with ID 999 doesn't exist" {
		t.Errorf("Error message should be displayed for invalid reportID. Got: %s", err.Error())
	}
}

func TestReportService_GetDownloadUrlPDF_Should_Return_URL_And_Password(t *testing.T) {
	client, mux, _, teardown := setup()
	signedUrl := "http://example.com/signed/download/url/pdf"
	password := "test_password"
	defer teardown()
	mux.HandleFunc("/api/v2/reports/1/pdf/", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		respBody := fmt.Sprintf(`{"url": "%s", "password": "%s"}`, signedUrl, password)
		fmt.Fprint(w, respBody)
	})
	url, pwd, err := client.Reports.GetDownloadUrlPDF(context.Background(), 1)
	if err != nil {
		t.Errorf("Reports.GetDownloadUrlPDF returned error %v", err)
	}
	if url != signedUrl {
		t.Errorf("Reports.GetDownloadUrlPDF returned incorrect url. Expected %s Got %s", signedUrl, url)
	}
	if pwd != password {
		t.Errorf("Reports.GetDownloadUrlPDF returned incorrect password. Expected %s Got %s", password, pwd)
	}
}

func TestReportService_GetDownloadUrlPDF_Should_Throw_Error_For_404(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()
	mux.HandleFunc("/api/v2/reports/999/pdf/", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"detail":"Not found."}`)
	})
	url, pwd, err := client.Reports.GetDownloadUrlPDF(context.Background(), 999)
	if url != "" || pwd != "" {
		t.Errorf("Url and password should be empty for invalid report id")
	}
	if err.Error() != "Report with ID 999 is not ready yet. Please wait for PDF generation to complete." {
		t.Errorf("Error message should be displayed for invalid reportID. Got: %s", err.Error())
	}
}
