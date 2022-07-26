package appknox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type ReportsService service

type Report struct {
	URL string `json:"url"`
}

type ReportResult struct {
	ID          int    `json:"id"`
	GeneratedOn string `json:"generated_on"`
	Language    string `json:"language"`
	Progress    int    `json:"progress"`
	Rating      string `json:"rating"`
}

// GenerateReport generates a report for the specified file.
func (s *ReportsService) GenerateReport(ctx context.Context, fileID int) (*ReportResult, error) {
	url := fmt.Sprintf("api/v2/files/%d/reports", fileID)
	req, err := s.client.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}

	var resp ReportResult

	res, err := s.client.Do(ctx, req, &resp)
	if err != nil {
		if res.StatusCode == 400 {
			return nil, errors.New("A report is already being generated or scan is in progress. Please wait.")
		}
		if res.StatusCode == 404 {
			return nil, errors.New("File not found")
		}
		return nil, err
	}

	return &resp, nil
}

// FetchReportResult it will fetch report result by result id.
func (s *ReportsService) FetchReportResult(ctx context.Context, reportID int) (*ReportResult, error) {
	url := fmt.Sprintf("api/v2/reports/%d", reportID)
	req, err := s.client.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	var resp ReportResult

	_, err = s.client.Do(ctx, req, &resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

// FetchLastReportResult it will return last report result, report list api is responding in decending order.
func (s *ReportsService) FetchLastReportResult(ctx context.Context, fileID int) (*ReportResult, error) {
	url := fmt.Sprintf("api/v2/files/%d/reports", fileID)
	req, err := s.client.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	type ReportResultList struct {
		Results []*ReportResult `json:"results"`
	}

	var resp ReportResultList

	_, err = s.client.Do(ctx, req, &resp)
	if err != nil {
		return nil, err
	}

	if len(resp.Results) > 0 {
		return resp.Results[0], nil
	}
	return nil, errors.New("No report results found")
}

// GetReportURL returns the url of the report file to download.
func (s *ReportsService) GetReportURL(ctx context.Context, reportID int) (*Report, error) {
	u := fmt.Sprintf("api/v2/reports/%d/pdf", reportID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	var reportResponse Report

	_, err = s.client.Do(ctx, req, &reportResponse)
	if err != nil {
		return nil, err
	}

	return &reportResponse, nil
}

// DownloadFile downloads the report file to the specified directory.
func (s *ReportsService) DownloadFile(ctx context.Context, url string, outputDir string) (string, error) {

	// Generating filename from download url
	filename := strings.Split(strings.Split(url, "?")[0], "/")[len(strings.Split(url, "/"))-1]

	outputPath := filepath.Join(outputDir, filename)

	// Creating output file from output path
	out, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	// Downloading file
	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != 200 {
		if resp.StatusCode != 200 {
			err = errors.New(`resource not found`)
		}
		return "", err
	}
	defer resp.Body.Close()

	// Writing file to output file
	_, err = io.Copy(out, resp.Body)

	return outputPath, err
}
