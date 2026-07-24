package appknox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type ReportsService service

type ReportResult struct {
	ID          int        `json:"id"`
	FileID      int        `json:"file_id"`
	GeneratedOn *time.Time `json:"generated_on"`
	Language    string     `json:"language"`
	Progress    int        `json:"progress"`
	Rating      string     `json:"rating"`
	IsKnoxIQ    bool       `json:"is_knoxiq"`
}
type DRFResponseReportDownloadUrl struct {
	Url string `json:"url"`
}

type DRFResponseReportDownloadPDF struct {
	Url      string `json:"url"`
	Password string `json:"password"`
}

// Get Signed URL to download Summary CSV report Data
func (s *ReportsService) GetDownloadUrlCSV(ctx context.Context, reportID int) (string, error) {
	url := fmt.Sprintf("/api/v2/reports/%d/summary_csv", reportID)
	request, err := s.client.NewRequest("GET", url, nil)
	var drfResponseReportDownloadUrl DRFResponseReportDownloadUrl
	resp, err := s.client.Do(ctx, request, &drfResponseReportDownloadUrl)
	if resp != nil && resp.StatusCode == 404 {
		id := strconv.Itoa(reportID)
		return "", errors.New("Report with ID " + id + " doesn't exist. Are you sure " + id + " is a reportID?")
	}
	return drfResponseReportDownloadUrl.Url, err

}
func (s *ReportsService) GetDownloadUrlExcel(ctx context.Context, reportID int) (string, error) {
	url := fmt.Sprintf("/api/v2/reports/%d/summary_excel", reportID)
	request, err := s.client.NewRequest("GET", url, nil)
	var drfResponseReportDownloadUrl DRFResponseReportDownloadUrl
	resp, err := s.client.Do(ctx, request, &drfResponseReportDownloadUrl)
	if resp != nil && resp.StatusCode == 404 {
		id := strconv.Itoa(reportID)
		return "", errors.New("Report with ID " + id + " doesn't exist. Are you sure " + id + " is a reportID?")
	}
	return drfResponseReportDownloadUrl.Url, err

}

// GetDownloadUrlPDF fetches the presigned PDF download URL and password for a report.
// Returns 404-style error if report is not yet generated (progress < 100).
func (s *ReportsService) GetDownloadUrlPDF(ctx context.Context, reportID int) (string, string, error) {
	url := fmt.Sprintf("/api/v2/reports/%d/pdf/", reportID)
	request, err := s.client.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", err
	}
	var drfResponseReportDownloadPDF DRFResponseReportDownloadPDF
	resp, err := s.client.Do(ctx, request, &drfResponseReportDownloadPDF)
	if resp != nil && resp.StatusCode == 404 {
		id := strconv.Itoa(reportID)
		return "", "", errors.New("Report with ID " + id + " is not ready yet. Please wait for PDF generation to complete.")
	}
	if err != nil {
		return "", "", err
	}
	return drfResponseReportDownloadPDF.Url, drfResponseReportDownloadPDF.Password, nil
}

// Download Report Data from Url to buffer.
// Absolute URLs (e.g. S3 presigned URLs) are fetched with a plain HTTP client
// to avoid sending an Authorization header alongside the presigned signature,
// which S3 rejects as having two auth mechanisms.
func (s *ReportsService) DownloadReportData(ctx context.Context, downloadUrl string) (bytes.Buffer, error) {
	var reportData bytes.Buffer

	if strings.HasPrefix(downloadUrl, "http://") || strings.HasPrefix(downloadUrl, "https://") {
		resp, err := http.Get(downloadUrl)
		if err != nil {
			return reportData, errors.New("We are facing issues while downloading the report.")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return reportData, errors.New("We are facing issues while downloading the report.")
		}
		_, err = reportData.ReadFrom(resp.Body)
		return reportData, err
	}

	request, err := s.client.NewRequest("GET", downloadUrl, nil)
	if err != nil {
		return reportData, err
	}
	resp, err := s.client.Reports.client.Do(ctx, request, &reportData)
	if resp != nil && resp.StatusCode != 200 {
		return reportData, errors.New("We are facing issues while downloading the report.")
	}
	return reportData, err
}

// Output report from buffer to file
func (s *ReportsService) WriteReportDataToFile(reportData bytes.Buffer, outputFilePath string) (string, error) {

	filePath := filepath.FromSlash(outputFilePath)
	dirPath := filepath.Dir(filePath)
	err := os.MkdirAll(dirPath, os.ModePerm)
	if err != nil {
		return "", err
	}
	out, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer out.Close()
	_, err = out.Write(reportData.Bytes())
	return outputFilePath, err
}

func (s *ReportsService) CreateReport(ctx context.Context, fileID int) (report *ReportResult, alreadyExists bool, err error) {
	url := fmt.Sprintf("api/v2/files/%d/reports", fileID)
	request, err := s.client.NewRequest("POST", url, nil)
	if err != nil {
		return nil, false, err
	}
	var reportResult ReportResult
	_, err = s.client.Do(ctx, request, &reportResult)
	if err != nil {
		if errResp, ok := err.(*ErrorResponse); ok && errResp.Response.StatusCode == 400 {
			// 400 means a report already exists and is up-to-date
			return nil, true, nil
		}
		return nil, false, err
	}
	return &reportResult, false, nil
}

type DRFListResponseReportResult struct {
	Results []ReportResult `json:"results"`
}

// GetLatestReport fetches the latest completed report for a file.
// Used as fallback when CreateReport returns 400 (report already up-to-date).
func (s *ReportsService) GetLatestReport(ctx context.Context, fileID int) (*ReportResult, error) {
	url := fmt.Sprintf("api/v2/files/%d/reports", fileID)
	request, err := s.client.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	var listResponse DRFListResponseReportResult
	_, err = s.client.Do(ctx, request, &listResponse)
	if err != nil {
		return nil, err
	}
	if len(listResponse.Results) == 0 {
		return nil, errors.New("no reports found for file " + strconv.Itoa(fileID))
	}
	return &listResponse.Results[0], nil
}

// GetReport fetches the current state of a report (used for polling progress).
func (s *ReportsService) GetReport(ctx context.Context, reportID int) (*ReportResult, error) {
	url := fmt.Sprintf("/api/v2/reports/%d/", reportID)
	request, err := s.client.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	var reportResult ReportResult
	resp, err := s.client.Do(ctx, request, &reportResult)
	if resp != nil && resp.StatusCode == 404 {
		id := strconv.Itoa(reportID)
		return nil, errors.New("Report with ID " + id + " doesn't exist")
	}
	if err != nil {
		return nil, err
	}
	return &reportResult, nil
}
