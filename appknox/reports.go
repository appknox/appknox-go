package appknox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type ReportsService service

type HIPAAPreferences struct {
	ShowHIPPA   bool `json:"value"`
	IsInherited bool `json:"is_inherited"`
}
type PCIDSSPreferences struct {
	ShowPCIDSS  bool `json:"value"`
	IsInherited bool `json:"is_inherited"`
}

type ReportPreferences struct {
	ShowAPIScan         bool              `json:"show_api_scan"`
	ShowManualScan      bool              `json:"show_manual_scan"`
	ShowStaticScan      bool              `json:"show_static_scan"`
	ShowDynamicScan     bool              `json:"show_dynamic_scan"`
	ShowIgnoredAnalyses bool              `json:"show_ignored_analyses_scan"`
	PCIDSSPreferences   PCIDSSPreferences `json:"show_hipaa"`
	HIPAAPreferences    HIPAAPreferences  `json:"show_pcidss"`
}

type ReportResult struct {
	ID                int               `json:"id"`
	GeneratedOn       *time.Time        `json:"generated_on"`
	Language          string            `json:"language"`
	Progress          int               `json:"progress"`
	Rating            string            `json:"rating"`
	ReportPreferences ReportPreferences `json:"preferences"`
}

type DRFResponseReport struct {
	Count    int             `json:"count,omitempty"`
	Next     string          `json:"next,omitempty"`
	Previous string          `json:"previous,omitempty"`
	Results  []*ReportResult `json:"results"`
}
type DRFResponseReportDownloadUrl struct {
	Url string `json:"url"`
}

func (s *ReportsService) List(ctx context.Context, fileID int) ([]*ReportResult, error) {
	url := fmt.Sprintf("api/v2/files/%d/reports", fileID)
	request, err := s.client.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	var drfResponseReport DRFResponseReport

	resp, err := s.client.Do(ctx, request, &drfResponseReport)
	if resp != nil && resp.StatusCode == 404 {
		id := strconv.Itoa(fileID)
		return nil, errors.New("Reports for fileID " + id + " doesn't exist. Are you sure " + id + " is a fileID?")
	}
	if err != nil {
		return nil, err
	}

	return drfResponseReport.Results, nil

	// return drfResponse.Results, &resp, nil

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

//Output report from buffer to terminal
func (s *ReportsService) WriteReportDataToTerminal(reportData bytes.Buffer) error {
	for {
		line, err := reportData.ReadBytes('\n')
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Println(string(line))
	}
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
