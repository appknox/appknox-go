package appknox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// KnoxFixerService talks to Mycroft's knoxfixer job API. The CLI never talks
// to the KnoxFixer service or any LLM directly, and never sends prompts.
type KnoxFixerService service

const knoxFixerSessionHeader = "X-Knoxfixer-Session"

// KnoxFixerAPIError is a Mycroft error with a stable machine code.
type KnoxFixerAPIError struct {
	StatusCode int
	Code       string `json:"code"`
	Detail     string `json:"detail"`
	JobID      int    `json:"job_id,omitempty"`
}

func (e *KnoxFixerAPIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s (%d %s)", e.Detail, e.StatusCode, e.Code)
	}
	return fmt.Sprintf("knoxfixer API error %d %s", e.StatusCode, e.Code)
}

// KnoxFixerCreateJobRequest is the body of POST /jobs: typed fields only.
type KnoxFixerCreateJobRequest struct {
	FileID              int    `json:"file_id"`
	RepoURL             string `json:"repo_url"`
	BaseBranch          string `json:"base_branch"`
	CIProvider          string `json:"ci_provider"`
	LikelihoodThreshold string `json:"likelihood_threshold"`
}

// KnoxFixerJob is the create/attach response.
type KnoxFixerJob struct {
	JobID      int    `json:"job_id"`
	CLISession string `json:"cli_session"`
	Status     string `json:"status"`
	Attached   bool   `json:"attached"`
}

// KnoxFixerToolCall is one tool the fix agent wants run in the repository.
type KnoxFixerToolCall struct {
	ID    string                 `json:"id"`
	Name  string                 `json:"name"`
	Input map[string]interface{} `json:"input"`
}

// KnoxFixerToolResult is the outcome of one tool call.
type KnoxFixerToolResult struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

// KnoxFixerSkipped is a finding that was not fixed (PR body / summary).
type KnoxFixerSkipped struct {
	Ref    string `json:"ref"`
	Title  string `json:"title,omitempty"`
	Reason string `json:"reason"`
}

// KnoxFixerPRText is the PR title/body generated server side.
type KnoxFixerPRText struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// KnoxFixerPayload holds every field any message type may carry.
type KnoxFixerPayload struct {
	// prepare
	BaseBranch string `json:"base_branch,omitempty"`
	HeadBranch string `json:"head_branch,omitempty"`
	// tools
	Calls []KnoxFixerToolCall `json:"calls,omitempty"`
	// finish
	PR            *KnoxFixerPRText   `json:"pr,omitempty"`
	CommitMessage string             `json:"commit_message,omitempty"`
	Fixed         []KnoxFixerFixed   `json:"fixed,omitempty"`
	Skipped       []KnoxFixerSkipped `json:"skipped,omitempty"`
	// done / failed
	Message string `json:"message,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// KnoxFixerMessage is one worker → CLI message from GET /next.
type KnoxFixerMessage struct {
	Type    string           `json:"type"`
	Seq     int              `json:"seq"`
	Payload KnoxFixerPayload `json:"payload"`
}

// KnoxFixerContextRequest answers `prepare`: the PR in use, files that
// conflicted when merging base into it, and the repository file list (paths).
type KnoxFixerContextRequest struct {
	InReplyToSeq    int      `json:"in_reply_to_seq"`
	PRURL           *string  `json:"pr_url,omitempty"`
	ConflictFiles   []string `json:"conflict_files"`
	RepoFiles       []string `json:"repo_files"`
	VerifyAvailable bool     `json:"verify_available"`
}

// KnoxFixerToolResultsRequest answers a `tools` message.
type KnoxFixerToolResultsRequest struct {
	InReplyToSeq int                   `json:"in_reply_to_seq"`
	Results      []KnoxFixerToolResult `json:"results"`
}

// KnoxFixerFixed reports the files patched for one fixed finding.
type KnoxFixerFixed struct {
	Ref          string   `json:"ref"`
	FilesPatched []string `json:"files_patched"`
}

// KnoxFixerCompleteRequest reports commit / push / PR results.
type KnoxFixerCompleteRequest struct {
	InReplyToSeq int                `json:"in_reply_to_seq"`
	PRURL        *string            `json:"pr_url,omitempty"`
	Title        string             `json:"title,omitempty"`
	CommitSHA    *string            `json:"commit_sha,omitempty"`
	Fixed        []KnoxFixerFixed   `json:"fixed"`
	Skipped      []KnoxFixerSkipped `json:"skipped,omitempty"`
}

// KnoxFixerAbortRequest reports a CLI side failure.
type KnoxFixerAbortRequest struct {
	InReplyToSeq int    `json:"in_reply_to_seq,omitempty"`
	Reason       string `json:"reason"`
	Message      string `json:"message,omitempty"`
}

func (s *KnoxFixerService) do(ctx context.Context, method, path, session string, body, out interface{}) (int, error) {
	req, err := s.client.NewRequest(method, path, body)
	if err != nil {
		return 0, err
	}
	req = req.WithContext(ctx)
	if session != "" {
		req.Header.Set(knoxFixerSessionHeader, session)
	}
	resp, err := s.client.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &KnoxFixerAPIError{StatusCode: resp.StatusCode}
		_ = json.Unmarshal(data, apiErr)
		if apiErr.Code == "" {
			apiErr.Code = http.StatusText(resp.StatusCode)
		}
		return resp.StatusCode, apiErr
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// CreateJob creates a knoxfixer job, or attaches to (takes over) the active
// job on the same file.
func (s *KnoxFixerService) CreateJob(ctx context.Context, body *KnoxFixerCreateJobRequest) (*KnoxFixerJob, error) {
	var job KnoxFixerJob
	if _, err := s.do(ctx, "POST", "api/knoxiq/knoxfixer/jobs", "", body, &job); err != nil {
		return nil, err
	}
	return &job, nil
}

// Next long-polls for the current worker message with seq > afterSeq.
func (s *KnoxFixerService) Next(ctx context.Context, jobID int, session string, afterSeq, waitSeconds int) (*KnoxFixerMessage, error) {
	query := url.Values{}
	query.Set("after_seq", strconv.Itoa(afterSeq))
	query.Set("wait", strconv.Itoa(waitSeconds))
	path := fmt.Sprintf("api/knoxiq/knoxfixer/jobs/%d/next?%s", jobID, query.Encode())
	var msg KnoxFixerMessage
	if _, err := s.do(ctx, "GET", path, session, nil, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// SendContext answers the `prepare` message.
func (s *KnoxFixerService) SendContext(ctx context.Context, jobID int, session string, body *KnoxFixerContextRequest) error {
	_, err := s.do(ctx, "POST", fmt.Sprintf("api/knoxiq/knoxfixer/jobs/%d/context", jobID), session, body, nil)
	return err
}

// SendToolResults answers a `tools` message with the results of the calls.
func (s *KnoxFixerService) SendToolResults(ctx context.Context, jobID int, session string, body *KnoxFixerToolResultsRequest) error {
	_, err := s.do(ctx, "POST", fmt.Sprintf("api/knoxiq/knoxfixer/jobs/%d/tool_results", jobID), session, body, nil)
	return err
}

// Complete reports the commit / push / PR result.
func (s *KnoxFixerService) Complete(ctx context.Context, jobID int, session string, body *KnoxFixerCompleteRequest) (string, error) {
	var out struct {
		Status string `json:"status"`
	}
	_, err := s.do(ctx, "POST", fmt.Sprintf("api/knoxiq/knoxfixer/jobs/%d/complete", jobID), session, body, &out)
	return out.Status, err
}

// Abort reports a CLI side failure.
func (s *KnoxFixerService) Abort(ctx context.Context, jobID int, session string, body *KnoxFixerAbortRequest) error {
	_, err := s.do(ctx, "POST", fmt.Sprintf("api/knoxiq/knoxfixer/jobs/%d/abort", jobID), session, body, nil)
	return err
}
