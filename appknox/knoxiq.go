package appknox

import (
	"context"
	"encoding/json"
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
	ID             int                     `json:"id,omitempty"`
	File           int                     `json:"file,omitempty"`
	Repo           string                  `json:"repo"`
	BaseBranch     string                  `json:"base_branch"`
	Branch         string                  `json:"branch"`
	PRURL          string                  `json:"pr_url"`
	CommitSHA      string                  `json:"commit_sha,omitempty"`
	PatchedFiles   []string                `json:"patched_files,omitempty"`
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

// Autofix job status labels from GET /api/knoxiq/file/{id}/autofix/{job_id}/.
const (
	AutofixStatusPending    = "Pending"
	AutofixStatusProcessing = "Processing"
	AutofixStatusReady      = "Ready"
	AutofixStatusProcessed  = "Processed"
	AutofixStatusErrored    = "Errored"
	AutofixStatusTimedOut   = "Timed Out"
)

// AutofixStart is the checkout Mycroft records when a job is created.
// Repo and BaseRef are required. RiskThreshold uses the same scale as
// analyses (low=1); zero is omitted so Mycroft applies its own default.
type AutofixStart struct {
	Repo          string `json:"repo"`
	BaseRef       string `json:"base_ref"`
	HeadRef       string `json:"head_ref,omitempty"`
	CommitSHA     string `json:"commit_sha,omitempty"`
	RiskThreshold int    `json:"risk_threshold,omitempty"`
}

// AutofixUnit is one finding the CLI walks. Remediation text stays on the
// worker; this is only enough to run turns and print an outcome.
type AutofixUnit struct {
	UnitID          string `json:"unit_id"`
	VulnerabilityID *int   `json:"vulnerability_id"`
	Finding         string `json:"finding"`
	Title           string `json:"title"`
	// Pointers because the worker sends JSON null for a field the unit does not have.
	ThirdParty *bool   `json:"third_party"`
	SkipReason *string `json:"skip_reason"`
}

// AutofixPRText is the title and body Sherrinford wrote for the pull request.
type AutofixPRText struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// AutofixToolCall is one tool the CLI runs on its checkout.
type AutofixToolCall struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

// AutofixToolResult is the CLI's answer to one tool call.
type AutofixToolResult struct {
	ID      string `json:"id"`
	Content string `json:"content,omitempty"`
	IsError bool   `json:"is_error,omitempty"`
}

// AutofixTurnStart opens a locate turn or a fix turn on one file.
//
// Nothing here is prompt text. The profile is typed values, the violation a
// rule name plus the gate's report (quoted to the model as data), and the
// targets are paths: Mycroft takes each file's reason from the locate answer.
type AutofixTurnStart struct {
	Kind      string            `json:"kind"`
	Target    *AutofixTarget    `json:"target,omitempty"`
	Others    []AutofixTarget   `json:"others,omitempty"`
	Profile   *AutofixProfile   `json:"profile,omitempty"`
	Violation *AutofixViolation `json:"violation,omitempty"`
}

// AutofixTarget is one file a fix turn may change.
type AutofixTarget struct {
	Path string `json:"path"`
	New  bool   `json:"new,omitempty"`
}

// AutofixProfile is the build facts read off the checkout.
type AutofixProfile struct {
	BuildSystem string `json:"build_system,omitempty"` // "Gradle", "Maven" or ""
	Android     bool   `json:"android,omitempty"`
	AGPMajor    int    `json:"agp_major,omitempty"`
	CompileSDK  int    `json:"compile_sdk,omitempty"`
	BuildConfig *bool  `json:"build_config,omitempty"` // nil when not checked
}

// AutofixViolation is why the patch gate refused the last attempt.
type AutofixViolation struct {
	Rule   string `json:"rule"`
	Detail string `json:"detail,omitempty"`
}

// AutofixTurnRequest is one call of a turn. Start opens it; ToolResults continue it.
type AutofixTurnRequest struct {
	UnitID      string              `json:"unit_id"`
	Start       *AutofixTurnStart   `json:"start,omitempty"`
	ToolResults []AutofixToolResult `json:"tool_results,omitempty"`
}

// AutofixTurnResponse is either tool calls or the end of the turn.
type AutofixTurnResponse struct {
	Type   string            `json:"type"`
	Calls  []AutofixToolCall `json:"calls"`
	Answer json.RawMessage   `json:"answer"`
	Failed bool              `json:"failed"`
	Detail string            `json:"detail"`
}

// AutofixTargetOutcome is one file's result inside a completed finding.
type AutofixTargetOutcome struct {
	Path    string `json:"path"`
	Patched bool   `json:"patched,omitempty"`
	Reason  string `json:"reason,omitempty"`
	New     bool   `json:"new,omitempty"`
}

// AutofixOutcome is one finding's result, posted to complete the job.
type AutofixOutcome struct {
	UnitID          string                 `json:"unit_id"`
	VulnerabilityID *int                   `json:"vulnerability_id"`
	Finding         string                 `json:"finding,omitempty"`
	Title           string                 `json:"title,omitempty"`
	Status          string                 `json:"status"`
	Detail          string                 `json:"detail,omitempty"`
	Files           []AutofixTargetOutcome `json:"files,omitempty"`
}

// AutofixRequest is one autofix job for a scanned file.
type AutofixRequest struct {
	ID           int            `json:"id,omitempty"`
	File         int            `json:"file,omitempty"`
	Project      int            `json:"project,omitempty"`
	Status       string         `json:"status"`
	PRURL        string         `json:"pr_url"`
	ErrorMessage string         `json:"error_message,omitempty"`
	Repo         string         `json:"repo,omitempty"`
	BaseRef      string         `json:"base_ref,omitempty"`
	HeadRef      string         `json:"head_ref,omitempty"`
	Step         int            `json:"step,omitempty"`
	Units        *[]AutofixUnit `json:"units"`
	PR           *AutofixPRText `json:"pr"`
	CreatedOn    *time.Time     `json:"created_on,omitempty"`
	UpdatedOn    *time.Time     `json:"updated_on,omitempty"`
}

// StartAutofix registers an autofix job (PENDING) and enqueues it.
// The CLI waits until Processing and the worker has published Units, then
// drives POST .../turn/ and POST .../complete/.
func (s *KnoxIQService) StartAutofix(ctx context.Context, fileID int, start *AutofixStart) (*AutofixRequest, *Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/autofix", fileID)
	var body interface{}
	if start != nil {
		body = start
	}
	req, err := s.client.NewRequest("POST", u, body)
	if err != nil {
		return nil, nil, err
	}
	var out AutofixRequest
	resp, err := s.client.Do(ctx, req, &out)
	return &out, resp, err
}

// GetAutofix returns one job, including units once the worker has built them.
func (s *KnoxIQService) GetAutofix(ctx context.Context, fileID, jobID int) (*AutofixRequest, *Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/autofix/%d", fileID, jobID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	var out AutofixRequest
	resp, err := s.client.Do(ctx, req, &out)
	return &out, resp, err
}

// AutofixTurn posts one model-turn call. Mycroft relays it to Sherrinford.
func (s *KnoxIQService) AutofixTurn(ctx context.Context, fileID, jobID int, turn *AutofixTurnRequest) (*AutofixTurnResponse, *Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/autofix/%d/turn", fileID, jobID)
	req, err := s.client.NewRequest("POST", u, turn)
	if err != nil {
		return nil, nil, err
	}
	var out AutofixTurnResponse
	resp, err := s.client.Do(ctx, req, &out)
	return &out, resp, err
}

// AutofixComplete posts every finding's outcome. The response is the job
// after the worker has written the pull-request text (status Ready or Processed).
func (s *KnoxIQService) AutofixComplete(ctx context.Context, fileID, jobID int, outcomes []AutofixOutcome) (*AutofixRequest, *Response, error) {
	u := fmt.Sprintf("api/knoxiq/file/%d/autofix/%d/complete", fileID, jobID)
	req, err := s.client.NewRequest("POST", u, map[string]any{"outcomes": outcomes})
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
