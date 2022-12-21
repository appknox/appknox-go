package appknox

import (
	"context"
	"errors"
	"fmt"
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

func (s *ReportsService) List(ctx context.Context, fileID int) ([]*ReportResult, error) {
	url := fmt.Sprintf("api/v2/files/%d/reports", fileID)
	request, err := s.client.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	var drfResponseReport DRFResponseReport

	resp, err := s.client.Do(ctx, request, &drfResponseReport)
	if resp.StatusCode == 404 {
		id := strconv.Itoa(fileID)
		return nil, errors.New("Reports for fileID " + id + " doesn't exist. Are you sure " + id + " is a fileID?")
	}
	if err != nil {
		return nil, err
	}

	return drfResponseReport.Results, nil

	// return drfResponse.Results, &resp, nil

}
