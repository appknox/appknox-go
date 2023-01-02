package appknox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type ReportsService service

type ReportResult struct {
	ID          int        `json:"id"`
	GeneratedOn *time.Time `json:"generated_on"`
	Language    string     `json:"language"`
	Progress    int        `json:"progress"`
	Rating      string     `json:"rating"`
}
type DRFResponseReportDownloadUrl struct {
	Url string `json:"url"`
}

//Get Signed URL to download Summary CSV report Data
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

//Download Report Data from Url to buffer
func (s *ReportsService) DownloadReportData(ctx context.Context, downloadUrl string) (bytes.Buffer, error) {

	request, err := s.client.NewRequest("GET", downloadUrl, nil)
	var reportData bytes.Buffer
	resp, err := s.client.Reports.client.Do(ctx, request, &reportData)
	if resp != nil && resp.StatusCode != 200 {
		return reportData, errors.New("We are facing issues while downloading the report.")
	}
	return reportData, err

}

//Output report from buffer to file
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

func (s *ReportsService) CreateReport(ctx context.Context, fileID int) (report *ReportResult, err error) {
	url := fmt.Sprintf("api/v2/files/%d/reports", fileID)
	request, err := s.client.NewRequest("POST", url, nil)
	var reportResult ReportResult
	_, err = s.client.Do(ctx, request, &reportResult)
	if err != nil {
		return nil, err
	}
	return &reportResult, nil
}
