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

// KnoxFixerLocate are the server's hints for finding a finding in the repo.
type KnoxFixerLocate struct {
	Kind        string   `json:"kind"`
	ClassNames  []string `json:"class_names"`
	PathGlobs   []string `json:"path_globs"`
	SearchTerms []string `json:"search_terms"`
}

// KnoxFixerPlanFinding is one finding the CLI must locate.
type KnoxFixerPlanFinding struct {
	Ref    string          `json:"ref"`
	Title  string          `json:"title"`
	Rule   string          `json:"rule"`
	Method string          `json:"method"`
	Locate KnoxFixerLocate `json:"locate"`
}

// KnoxFixerLimits are the per-finding snippet limits.
type KnoxFixerLimits struct {
	SnippetLinesPerFinding int `json:"snippet_lines_per_finding"`
	ExtraContextLines      int `json:"extra_context_lines"`
}

// KnoxFixerNeed is one extra line range asked for in the need_context step.
type KnoxFixerNeed struct {
	Ref       string `json:"ref"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// KnoxFixerEdit is a search/replace edit to apply in the repo.
type KnoxFixerEdit struct {
	Ref     string `json:"ref"`
	Path    string `json:"path"`
	Search  string `json:"search"`
	Replace string `json:"replace"`
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
	// plan
	BaseBranch string                 `json:"base_branch,omitempty"`
	HeadBranch string                 `json:"head_branch,omitempty"`
	Findings   []KnoxFixerPlanFinding `json:"findings,omitempty"`
	Limits     KnoxFixerLimits        `json:"limits,omitempty"`
	// need_context
	Need []KnoxFixerNeed `json:"need,omitempty"`
	// edits
	Edits         []KnoxFixerEdit    `json:"edits,omitempty"`
	PR            KnoxFixerPRText    `json:"pr,omitempty"`
	CommitMessage string             `json:"commit_message,omitempty"`
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

// KnoxFixerSnippet is a small line range of one file (never a whole file).
type KnoxFixerSnippet struct {
	Refs      []string `json:"refs"`
	Path      string   `json:"path"`
	StartLine int      `json:"start_line"`
	EndLine   int      `json:"end_line"`
	Content   string   `json:"content"`
}

// KnoxFixerContextRequest answers a plan or need_context message.
type KnoxFixerContextRequest struct {
	InReplyToSeq   int                `json:"in_reply_to_seq"`
	PRURL          *string            `json:"pr_url,omitempty"`
	ConflictFiles  []string           `json:"conflict_files,omitempty"`
	UnresolvedRefs []string           `json:"unresolved_refs,omitempty"`
	Snippets       []KnoxFixerSnippet `json:"snippets"`
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
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

// SendContext answers a plan / need_context message with snippets.
func (s *KnoxFixerService) SendContext(ctx context.Context, jobID int, session string, body *KnoxFixerContextRequest) error {
	_, err := s.do(ctx, "POST", fmt.Sprintf("api/knoxiq/knoxfixer/jobs/%d/context", jobID), session, body, nil)
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
