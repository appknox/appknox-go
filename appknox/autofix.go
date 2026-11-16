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

// AutofixService talks to Mycroft's knoxfixer job API. The CLI never talks
// to the Autofix service or any LLM directly, and never sends prompts.
type AutofixService service

const autofixSessionHeader = "X-Knoxfixer-Session"

// AutofixAPIError is a Mycroft error with a stable machine code.
type AutofixAPIError struct {
	StatusCode int
	Code       string `json:"code"`
	Detail     string `json:"detail"`
	JobID      int    `json:"job_id,omitempty"`
}

func (e *AutofixAPIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s (%d %s)", e.Detail, e.StatusCode, e.Code)
	}
	return fmt.Sprintf("knoxfixer API error %d %s", e.StatusCode, e.Code)
}

// AutofixCreateJobRequest is the body of POST /jobs: typed fields only.
type AutofixCreateJobRequest struct {
	FileID              int    `json:"file_id"`
	RepoURL             string `json:"repo_url"`
	BaseBranch          string `json:"base_branch"`
	CIProvider          string `json:"ci_provider"`
	LikelihoodThreshold string `json:"likelihood_threshold"`
}

// AutofixJob is the create/attach response.
type AutofixJob struct {
	JobID      int    `json:"job_id"`
	CLISession string `json:"cli_session"`
	Status     string `json:"status"`
	Attached   bool   `json:"attached"`
}

// AutofixToolCall is one tool the fix agent wants run in the repository.
type AutofixToolCall struct {
	ID    string                 `json:"id"`
	Name  string                 `json:"name"`
	Input map[string]interface{} `json:"input"`
}

// AutofixToolResult is the outcome of one tool call.
type AutofixToolResult struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

// AutofixSkipped is a finding that was not fixed (PR body / summary).
type AutofixSkipped struct {
	Ref    string `json:"ref"`
	Title  string `json:"title,omitempty"`
	Reason string `json:"reason"`
}

// AutofixPRText is the PR title/body generated server side.
type AutofixPRText struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// AutofixPayload holds every field any message type may carry.
type AutofixPayload struct {
	// prepare
	BaseBranch string `json:"base_branch,omitempty"`
	HeadBranch string `json:"head_branch,omitempty"`
	// tools
	Calls []AutofixToolCall `json:"calls,omitempty"`
	// finish
	PR            *AutofixPRText   `json:"pr,omitempty"`
	CommitMessage string           `json:"commit_message,omitempty"`
	Fixed         []AutofixFixed   `json:"fixed,omitempty"`
	Skipped       []AutofixSkipped `json:"skipped,omitempty"`
	// done / failed
	Message string `json:"message,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// AutofixMessage is one worker → CLI message from GET /next.
type AutofixMessage struct {
	Type    string         `json:"type"`
	Seq     int            `json:"seq"`
	Payload AutofixPayload `json:"payload"`
}

// AutofixContextRequest answers `prepare`: the PR in use, files that
// conflicted when merging base into it, and the repository file list (paths).
type AutofixContextRequest struct {
	InReplyToSeq    int      `json:"in_reply_to_seq"`
	PRURL           *string  `json:"pr_url,omitempty"`
	ConflictFiles   []string `json:"conflict_files"`
	RepoFiles       []string `json:"repo_files"`
	VerifyAvailable bool     `json:"verify_available"`
}

// AutofixToolResultsRequest answers a `tools` message.
type AutofixToolResultsRequest struct {
	InReplyToSeq int                 `json:"in_reply_to_seq"`
	Results      []AutofixToolResult `json:"results"`
}

// AutofixFixed reports the files patched for one fixed finding.
type AutofixFixed struct {
	Ref          string   `json:"ref"`
	FilesPatched []string `json:"files_patched"`
}

// AutofixCompleteRequest reports commit / push / PR results.
type AutofixCompleteRequest struct {
	InReplyToSeq int              `json:"in_reply_to_seq"`
	PRURL        *string          `json:"pr_url,omitempty"`
	Title        string           `json:"title,omitempty"`
	CommitSHA    *string          `json:"commit_sha,omitempty"`
	Fixed        []AutofixFixed   `json:"fixed"`
	Skipped      []AutofixSkipped `json:"skipped,omitempty"`
}

// AutofixAbortRequest reports a CLI side failure.
type AutofixAbortRequest struct {
	InReplyToSeq int    `json:"in_reply_to_seq,omitempty"`
	Reason       string `json:"reason"`
	Message      string `json:"message,omitempty"`
}

func (s *AutofixService) do(ctx context.Context, method, path, session string, body, out interface{}) (int, error) {
	req, err := s.client.NewRequest(method, path, body)
	if err != nil {
		return 0, err
	}
	req = req.WithContext(ctx)
	if session != "" {
		req.Header.Set(autofixSessionHeader, session)
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
		apiErr := &AutofixAPIError{StatusCode: resp.StatusCode}
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
func (s *AutofixService) CreateJob(ctx context.Context, body *AutofixCreateJobRequest) (*AutofixJob, error) {
	var job AutofixJob
	if _, err := s.do(ctx, "POST", "api/knoxiq/knoxfixer/jobs", "", body, &job); err != nil {
		return nil, err
	}
	return &job, nil
}

// Next long-polls for the current worker message with seq > afterSeq.
func (s *AutofixService) Next(ctx context.Context, jobID int, session string, afterSeq, waitSeconds int) (*AutofixMessage, error) {
	query := url.Values{}
	query.Set("after_seq", strconv.Itoa(afterSeq))
	query.Set("wait", strconv.Itoa(waitSeconds))
	path := fmt.Sprintf("api/knoxiq/knoxfixer/jobs/%d/next?%s", jobID, query.Encode())
	var msg AutofixMessage
	if _, err := s.do(ctx, "GET", path, session, nil, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// SendContext answers the `prepare` message.
func (s *AutofixService) SendContext(ctx context.Context, jobID int, session string, body *AutofixContextRequest) error {
	_, err := s.do(ctx, "POST", fmt.Sprintf("api/knoxiq/knoxfixer/jobs/%d/context", jobID), session, body, nil)
	return err
}

// SendToolResults answers a `tools` message with the results of the calls.
func (s *AutofixService) SendToolResults(ctx context.Context, jobID int, session string, body *AutofixToolResultsRequest) error {
	_, err := s.do(ctx, "POST", fmt.Sprintf("api/knoxiq/knoxfixer/jobs/%d/tool_results", jobID), session, body, nil)
	return err
}

// Complete reports the commit / push / PR result.
func (s *AutofixService) Complete(ctx context.Context, jobID int, session string, body *AutofixCompleteRequest) (string, error) {
	var out struct {
		Status string `json:"status"`
	}
	_, err := s.do(ctx, "POST", fmt.Sprintf("api/knoxiq/knoxfixer/jobs/%d/complete", jobID), session, body, &out)
	return out.Status, err
}

// Abort reports a CLI side failure.
func (s *AutofixService) Abort(ctx context.Context, jobID int, session string, body *AutofixAbortRequest) error {
	_, err := s.do(ctx, "POST", fmt.Sprintf("api/knoxiq/knoxfixer/jobs/%d/abort", jobID), session, body, nil)
	return err
}
