package appknox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type ReportsService service

type Report struct {
	URL string `json:"url"`
}

// GetReportURL returns the url of the report file to download.
func (s *ReportsService) GetReportURL(ctx context.Context, fileID int) (*Report, error) {
	u := fmt.Sprintf("api/hudson-api/reports/%d", fileID)
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

	var outputPath bytes.Buffer
	outputPath.WriteString(outputDir)
	outputPath.WriteString("/")
	outputPath.WriteString(filename)

	// Creating output file from output path
	out, err := os.Create(outputPath.String())
	if err != nil {
		fmt.Println(outputPath.String())
		return "", err
	}
	defer out.Close()

	// Downloading file
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Writing file to output file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", err
	}

	return outputPath.String(), nil
}
