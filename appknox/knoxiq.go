package appknox

import (
	"context"
	"fmt"
	"time"

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

// AutofixPRCommitRecord is one delivered commit on an AutofixPR.
type AutofixPRCommitRecord struct {
	ID           int        `json:"id,omitempty"`
	CommitSHA    string     `json:"commit_sha,omitempty"`
	PatchedFiles []string   `json:"patched_files,omitempty"`
	CreatedOn    *time.Time `json:"created_on,omitempty"`
}

// AutofixPR is a delivered autofix GitHub PR for one scanned file.
// CommitSHA and PatchedFiles are write-only on POST; the response lists them
// under Commits as AutofixPRCommitRecord rows.
type AutofixPR struct {
	ID           int      `json:"id,omitempty"`
	File         int      `json:"file,omitempty"`
	Repo         string   `json:"repo"`
	BaseBranch   string   `json:"base_branch"`
	Branch       string   `json:"branch"`
	PRURL        string   `json:"pr_url"`
	CommitSHA    string   `json:"commit_sha,omitempty"`
	PatchedFiles []string `json:"patched_files,omitempty"`
	// AutofixRequest is the job this delivery closes (write-only).
	AutofixRequest int                     `json:"autofix_request,omitempty"`
	Commits        []AutofixPRCommitRecord `json:"commits,omitempty"`
	CreatedOn      *time.Time              `json:"created_on,omitempty"`
	UpdatedOn      *time.Time              `json:"updated_on,omitempty"`
}

// CreateAutofixPR records a delivered autofix: upserts the PR, appends a commit.
func (s *KnoxIQService) CreateAutofixPR(ctx context.Context, fileID int, pr *AutofixPR) (*AutofixPR, *Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/autofix_prs", fileID)
	req, err := s.client.NewRequest("POST", u, pr)
	if err != nil {
		return nil, nil, err
	}
	var out AutofixPR
	resp, err := s.client.Do(ctx, req, &out)
	return &out, resp, err
}

// Autofix job status labels.
const (
	AutofixStatusPending     = "Pending"
	AutofixStatusProcessing  = "Processing"
	AutofixStatusAwaitingCLI = "Awaiting CLI"
	AutofixStatusReady       = "Ready"
	AutofixStatusProcessed   = "Processed"
	AutofixStatusErrored     = "Errored"
	AutofixStatusTimedOut    = "Timed Out"
)

// AutofixToolCall is one call Appknox asks the CLI to run on its checkout.
type AutofixToolCall struct {
	ID   string                 `json:"id"`
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args"`
}

// AutofixToolResult answers one AutofixToolCall: Content for file tools,
// Data for the structured validation and gate calls.
type AutofixToolResult struct {
	ID      string                 `json:"id"`
	Content string                 `json:"content"`
	IsError bool                   `json:"is_error"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// AutofixTargetOutcome is what happened to one file of one finding.
type AutofixTargetOutcome struct {
	Path    string `json:"path"`
	Patched bool   `json:"patched"`
	Reason  string `json:"reason"`
	New     bool   `json:"new"`
}

// AutofixOutcome is one KnoxIQ finding's result.
type AutofixOutcome struct {
	UnitID          string                 `json:"unit_id"`
	VulnerabilityID int                    `json:"vulnerability_id"`
	Finding         string                 `json:"finding"`
	Title           string                 `json:"title"`
	Status          string                 `json:"status"`
	Detail          string                 `json:"detail"`
	Files           []AutofixTargetOutcome `json:"files"`
}

// AutofixPRText is the pull request title and body Appknox wrote.
type AutofixPRText struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// AutofixRequest is one autofix job for a scanned file.
type AutofixRequest struct {
	ID           int               `json:"id,omitempty"`
	File         int               `json:"file,omitempty"`
	Project      int               `json:"project,omitempty"`
	Status       string            `json:"status"`
	Step         int               `json:"step"`
	ToolCalls    []AutofixToolCall `json:"tool_calls"`
	Outcomes     []AutofixOutcome  `json:"outcomes"`
	PR           *AutofixPRText    `json:"pr"`
	PRURL        string            `json:"pr_url"`
	ErrorMessage string            `json:"error_message,omitempty"`
	CreatedOn    *time.Time        `json:"created_on,omitempty"`
	UpdatedOn    *time.Time        `json:"updated_on,omitempty"`
}

// AutofixStart describes the CI checkout a job runs against.
type AutofixStart struct {
	Repo          string `json:"repo"`
	BaseRef       string `json:"base_ref"`
	HeadRef       string `json:"head_ref,omitempty"`
	CommitSHA     string `json:"commit_sha,omitempty"`
	RiskThreshold int    `json:"risk_threshold"`
}

// StartAutofix registers an autofix job for the file and queues it. Any older
// job for the file is superseded.
func (s *KnoxIQService) StartAutofix(ctx context.Context, fileID int, start *AutofixStart) (*AutofixRequest, *Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/autofix", fileID)
	req, err := s.client.NewRequest("POST", u, start)
	if err != nil {
		return nil, nil, err
	}
	var out AutofixRequest
	resp, err := s.client.Do(ctx, req, &out)
	return &out, resp, err
}

// GetAutofixRequest returns one job, with the tool calls it is waiting on.
func (s *KnoxIQService) GetAutofixRequest(ctx context.Context, fileID, requestID int) (*AutofixRequest, *Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/autofix/%d", fileID, requestID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	var out AutofixRequest
	resp, err := s.client.Do(ctx, req, &out)
	return &out, resp, err
}

// SubmitAutofixToolResults answers the tool calls of one step.
func (s *KnoxIQService) SubmitAutofixToolResults(ctx context.Context, fileID, requestID, step int, results []AutofixToolResult) (*Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/autofix/%d/tool_results", fileID, requestID)
	body := struct {
		Step    int                 `json:"step"`
		Results []AutofixToolResult `json:"results"`
	}{Step: step, Results: results}
	req, err := s.client.NewRequest("POST", u, body)
	if err != nil {
		return nil, err
	}
	return s.client.Do(ctx, req, nil)
}

// MarkAutofixRequestTimedOut gives up on one job.
func (s *KnoxIQService) MarkAutofixRequestTimedOut(ctx context.Context, fileID, requestID int) (*AutofixRequest, *Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/autofix/%d/timeout", fileID, requestID)
	req, err := s.client.NewRequest("POST", u, nil)
	if err != nil {
		return nil, nil, err
	}
	var out AutofixRequest
	resp, err := s.client.Do(ctx, req, &out)
	return &out, resp, err
}
