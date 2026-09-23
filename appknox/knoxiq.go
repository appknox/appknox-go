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
	ID           int                     `json:"id,omitempty"`
	File         int                     `json:"file,omitempty"`
	Repo         string                  `json:"repo"`
	BaseBranch   string                  `json:"base_branch"`
	Branch       string                  `json:"branch"`
	PRURL        string                  `json:"pr_url"`
	CommitSHA    string                  `json:"commit_sha,omitempty"`
	PatchedFiles []string                `json:"patched_files,omitempty"`
	Commits      []AutofixPRCommitRecord `json:"commits,omitempty"`
	CreatedOn    *time.Time              `json:"created_on,omitempty"`
	UpdatedOn    *time.Time              `json:"updated_on,omitempty"`
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

// Autofix job status labels from GET /api/knoxiq/file/{id}/autofix/status/.
const (
	AutofixStatusPending    = "Pending"
	AutofixStatusProcessing = "Processing"
	AutofixStatusProcessed  = "Processed"
	AutofixStatusErrored    = "Errored"
	AutofixStatusTimedOut   = "Timed Out"
)

// AutofixRequest is one autofix job for a scanned file.
type AutofixRequest struct {
	ID           int        `json:"id,omitempty"`
	File         int        `json:"file,omitempty"`
	Project      int        `json:"project,omitempty"`
	Status       string     `json:"status"`
	PRURL        string     `json:"pr_url"`
	ErrorMessage string     `json:"error_message,omitempty"`
	CreatedOn    *time.Time `json:"created_on,omitempty"`
	UpdatedOn    *time.Time `json:"updated_on,omitempty"`
}

// StartAutofix registers an autofix job for the file (PENDING) and enqueues
// it. The CLI waits until Processing, then locates, fixes, and records the PR.
func (s *KnoxIQService) StartAutofix(ctx context.Context, fileID int) (*AutofixRequest, *Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/autofix", fileID)
	req, err := s.client.NewRequest("POST", u, nil)
	if err != nil {
		return nil, nil, err
	}
	var out AutofixRequest
	resp, err := s.client.Do(ctx, req, &out)
	return &out, resp, err
}

// GetAutofixStatus returns the latest autofix job status for the file.
func (s *KnoxIQService) GetAutofixStatus(ctx context.Context, fileID int) (*AutofixRequest, *Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/autofix/status", fileID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	var out AutofixRequest
	resp, err := s.client.Do(ctx, req, &out)
	return &out, resp, err
}

// MarkAutofixTimedOut marks the in-flight autofix job as Timed Out.
func (s *KnoxIQService) MarkAutofixTimedOut(ctx context.Context, fileID int) (*AutofixRequest, *Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/autofix/timeout", fileID)
	req, err := s.client.NewRequest("POST", u, nil)
	if err != nil {
		return nil, nil, err
	}
	var out AutofixRequest
	resp, err := s.client.Do(ctx, req, &out)
	return &out, resp, err
}

// knoxiqPageLimit is the page size requested from the limit/offset endpoint.
const knoxiqPageLimit = 100

// KnoxIQRemediation is KnoxIQ's stored remediation for one finding.
type KnoxIQRemediation struct {
	Remediation  string   `json:"remediation"`
	Steps        []string `json:"steps"`
	CodeExamples []string `json:"code_examples"`
	References   []string `json:"references"`

	// Verification is KnoxIQ's own "how to confirm the fix worked" steps.
	//
	// Empty means "could not check", never "passed".
	//
	// TODO(autofix-verification): ALWAYS empty against the deployed KnoxIQ --
	// copilot-core's FindingRemediationResult does not model it on the branch
	// KnoxIQ ships from. The fix is copilot-core 6befb01, unreleased. Confirmed
	// against a live payload (file 412, analysis 40231) on 2026-09-09.
	//
	// Do NOT repoint this at poc.verification_steps: those are adb commands
	// proving the vulnerability is real BEFORE any fix, and cannot be matched
	// against a source diff. Switching would turn a silently-empty gate into a
	// permanently-failing one.
	Verification []string `json:"verification"`

	// Source records provenance: source_type, kb_id, llm_model, confidence.
	Source map[string]interface{} `json:"source"`
}

// KnoxIQValidation is KnoxIQ's verdict on whether a finding is real.
//
// This answers "is this finding genuine?", NOT "does this patch fix it?".
type KnoxIQValidation struct {
	Verdict         string   `json:"verdict"`
	Confidence      float64  `json:"confidence"`
	ConfidenceLabel string   `json:"confidence_label"`
	FindingSummary  string   `json:"finding_summary"`
	Reasoning       string   `json:"reasoning"`
	Evidence        []string `json:"evidence"`

	// IsValid is a pointer so an absent field stays distinguishable from an
	// explicit false. Absent means "not recorded" and is treated as valid;
	// Go's zero value would otherwise silently mark every such finding invalid.
	IsValid *bool `json:"is_valid"`

	// IsThirdParty reports whether the flagged class is vendored rather than
	// first-party. nil means unknown -- and unknown is not third-party.
	IsThirdParty  *bool   `json:"is_third_party"`
	LibraryOrigin *string `json:"library_origin"`
}

// KnoxIQFinding is one KnoxIQ finding -- a single flagged class in an analysis.
type KnoxIQFinding struct {
	FindingID       string             `json:"finding_id"`
	Title           string             `json:"title"`
	Description     string             `json:"description"`
	Remediation     *KnoxIQRemediation `json:"remediation"`
	Validation      *KnoxIQValidation  `json:"validation"`
	DeveloperPrompt string             `json:"developer_prompt"`
}

// DRFResponseKnoxIQFinding is the DRF envelope for the findings endpoint.
type DRFResponseKnoxIQFinding struct {
	Count    int              `json:"count"`
	Next     string           `json:"next,omitempty"`
	Previous string           `json:"previous,omitempty"`
	Results  []*KnoxIQFinding `json:"results"`
}

// ListByAnalysis returns every KnoxIQ finding recorded for an Appknox analysis.
//
// An empty result is NOT an error: it means KnoxIQ has not processed this
// analysis, or judged nothing worth reporting. Transport failures and 5xx are
// retried (see knoxiq_retry.go) and then returned -- callers must not fall back
// to metadata-derived remediation, because a fix built on guessed guidance is
// worse than no fix at all.
//
// One Appknox analysis maps to MANY KnoxIQ findings (one per flagged class).
func (s *KnoxIQService) ListByAnalysis(ctx context.Context, analysisID int) ([]*KnoxIQFinding, error) {
	url := fmt.Sprintf("api/knoxiq/analyses/%v/findings?limit=%d", analysisID, knoxiqPageLimit)

	var response DRFResponseKnoxIQFinding
	if err := s.getWithRetry(ctx, url, &response); err != nil {
		return nil, fmt.Errorf("knoxiq: listing findings for analysis %d: %w", analysisID, err)
	}
	// One page only (see knoxiqPageLimit) -- deliberately NOT paginated here.
	// Silently returning a partial result is worse than returning it loudly:
	// say so, so a caller attempting a fix from a truncated finding set knows
	// why it may be incomplete, rather than assuming this was everything.
	if response.Count > len(response.Results) {
		fmt.Printf("knoxiq: analysis %d has %d finding(s), only %d fetched (no pagination)\n",
			analysisID, response.Count, len(response.Results))
	}
	return response.Results, nil
}
