package appknox

import (
	"context"
	"fmt"

	"github.com/appknox/appknox-go/appknox/enums"
)

// KnoxIQService handles communication with the KnoxIQ related methods of the Appknox API.
type KnoxIQService service

// KnoxIQ scan status values from GET /api/knoxiq/file/{id}/knoxiq_scan/status.
const (
	KnoxIQScanStatusLegacy       = -1
	KnoxIQScanStatusDisabled     = 0
	KnoxIQScanStatusNotTriggered = 1
	KnoxIQScanStatusPending      = 2
	KnoxIQScanStatusRunning      = 3
	KnoxIQScanStatusCompleted    = 4
	KnoxIQScanStatusErrored      = 5
)

var knoxIQScanStatusLabels = map[int]string{
	KnoxIQScanStatusLegacy:       "Legacy",
	KnoxIQScanStatusDisabled:     "Disabled",
	KnoxIQScanStatusNotTriggered: "Not Triggered",
	KnoxIQScanStatusPending:      "Pending",
	KnoxIQScanStatusRunning:      "Running",
	KnoxIQScanStatusCompleted:    "Completed",
	KnoxIQScanStatusErrored:      "Errored",
}

// KnoxIQScanStatusLabel is the Mycroft label for a scan-status int.
func KnoxIQScanStatusLabel(v int) string {
	if s, ok := knoxIQScanStatusLabels[v]; ok {
		return s
	}
	return fmt.Sprintf("Unknown(%d)", v)
}

// KnoxIQFileScanStatus is the file-level SAST/DAST KnoxIQ status.
type KnoxIQFileScanStatus struct {
	ID         int `json:"id,omitempty"`
	SASTStatus int `json:"sast_status"`
	DASTStatus int `json:"dast_status"`
}

// Completed reports whether KnoxIQ has finished for autofix.
// SAST complete is enough; DAST-only files (SAST disabled) need DAST complete.
func (s *KnoxIQFileScanStatus) Completed() bool {
	if s == nil {
		return false
	}
	if s.SASTStatus == KnoxIQScanStatusCompleted {
		return true
	}
	return s.SASTStatus == KnoxIQScanStatusDisabled &&
		s.DASTStatus == KnoxIQScanStatusCompleted
}

// KnoxIQCICDAnalysis represents one triaged analysis row for the CI/CD pipeline.
type KnoxIQCICDAnalysis struct {
	ID                       int                       `json:"id,omitempty"`
	ComputedRisk             enums.RiskType            `json:"computed_risk,omitempty"`
	OverriddenRisk           enums.RiskType            `json:"overridden_risk,omitempty"`
	CvssVector               string                    `json:"cvss_vector,omitempty"`
	CvssBase                 float64                   `json:"cvss_base,omitempty"`
	VulnerabilityID          int                       `json:"vulnerability_id,omitempty"`
	VulnerabilityName        string                    `json:"vulnerability_name,omitempty"`
	ExploitabilityScore      *float64                  `json:"exploitability_score"`
	ExploitabilityLikelihood *enums.ExploitabilityType `json:"exploitability_likelihood"`
	IsKnoxIQAllFP            bool                      `json:"is_knoxiq_all_fp"`
	NeedsReview              bool                      `json:"needs_review"`
}

// DRFResponseKnoxIQCICDAnalysis is the paginated response wrapper for the KnoxIQ CI/CD analyses api.
type DRFResponseKnoxIQCICDAnalysis struct {
	Count    int                   `json:"count,omitempty"`
	Next     string                `json:"next,omitempty"`
	Previous string                `json:"previous,omitempty"`
	Results  []*KnoxIQCICDAnalysis `json:"results"`
}

// GetScanStatus returns KnoxIQ SAST/DAST status for a file.
func (s *KnoxIQService) GetScanStatus(ctx context.Context, fileID int) (*KnoxIQFileScanStatus, *Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/knoxiq_scan/status", fileID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	var out KnoxIQFileScanStatus
	resp, err := s.client.Do(ctx, req, &out)
	return &out, resp, err
}

// ListCICDAnalyses lists the triaged analyses for a file.
func (s *KnoxIQService) ListCICDAnalyses(ctx context.Context, fileID int, opt *AnalysisListOptions) ([]*KnoxIQCICDAnalysis, *DRFResponseKnoxIQCICDAnalysis, error) {
	u := fmt.Sprintf("api/knoxiq/file/%v/cicd_analyses", fileID)
	URL, err := addOptions(u, opt)
	if err != nil {
		return nil, nil, err
	}
	req, err := s.client.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, nil, err
	}
	var drfResponse DRFResponseKnoxIQCICDAnalysis
	_, err = s.client.Do(ctx, req, &drfResponse)
	if err != nil {
		if StatusCodeOf(err) == 404 {
			return nil, nil, fmt.Errorf("KnoxIQ CI/CD analyses for fileID %d not found (404)", fileID)
		}
		return nil, nil, err
	}
	return drfResponse.Results, &drfResponse, nil
}
