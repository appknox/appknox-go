// Package fixservice is a thin client for the hosted Appknox fix endpoint:
// submit one located file + remediation, poll the async job to completion, and
// fetch the patch. The provider LLM key stays server-side; this client holds
// only a scoped bearer token.
package fixservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultPollInterval = time.Second
	defaultMaxPolls     = 180
	requestTimeout      = 130 * time.Second
	maxResponseBytes    = 16 << 20 // cap any fix-service response (OOM / disk-fill guard)
)

var terminal = map[string]bool{"succeeded": true, "failed": true, "expired": true}

// Config points the client at the fix service with its scoped token.
type Config struct {
	URL          string        // base URL, e.g. http://localhost:8100
	Token        string        // scoped fix-service token (sent as Bearer)
	PollInterval time.Duration // 0 = default (1s)
	MaxPolls     int           // 0 = default (180)
}

func (c Config) base() string { return strings.TrimRight(c.URL, "/") }

// Request is the single-file fix payload (matches the service FixRequest).
type Request struct {
	Filename    string `json:"filename"`
	FileContent string `json:"file_content"`
	Remediation string `json:"remediation"`
	Finding     string `json:"finding,omitempty"`
	Language    string `json:"language,omitempty"`
}

// Result is the fix outcome (matches the service FixResponse).
type Result struct {
	Changed        bool    `json:"changed"`
	PatchedContent string  `json:"patched_content"`
	UnifiedDiff    string  `json:"unified_diff"`
	Confidence     float64 `json:"confidence"`
}

// SubmitAndAwait submits a fix job, polls until terminal, and returns the result.
func SubmitAndAwait(ctx context.Context, cfg Config, req Request) (Result, error) {
	if err := ValidateEndpoint(cfg.base()); err != nil {
		return Result{}, err
	}
	jobID, err := submit(ctx, cfg, req)
	if err != nil {
		return Result{}, err
	}
	if err := poll(ctx, cfg, jobID); err != nil {
		return Result{}, err
	}
	return fetchResult(ctx, cfg, jobID)
}

// submit posts the job and returns its id (202 + {job_id}).
func submit(ctx context.Context, cfg Config, req Request) (string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	httpReq, err := newRequest(ctx, http.MethodPost, cfg.base()+"/v1/fix/jobs", cfg.Token, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Idempotency-Key", idempotencyKey(req))

	var out struct {
		JobID string `json:"job_id"`
	}
	if err := doJSON(httpReq, &out); err != nil {
		return "", err
	}
	if out.JobID == "" {
		return "", errors.New("fixservice: submit returned no job_id")
	}
	return out.JobID, nil
}

// poll waits for the job to reach a terminal state, erroring on non-success.
func poll(ctx context.Context, cfg Config, jobID string) error {
	interval, maxPolls := cfg.PollInterval, cfg.MaxPolls
	if interval <= 0 {
		interval = defaultPollInterval
	}
	if maxPolls <= 0 {
		maxPolls = defaultMaxPolls
	}
	statusURL := fmt.Sprintf("%s/v1/fix/jobs/%s", cfg.base(), url.PathEscape(jobID))
	for i := 0; i < maxPolls; i++ {
		var st struct {
			Status string `json:"status"`
		}
		req, err := newRequest(ctx, http.MethodGet, statusURL, cfg.Token, nil)
		if err != nil {
			return err
		}
		if err := doJSON(req, &st); err != nil {
			return err
		}
		if terminal[st.Status] {
			if st.Status != "succeeded" {
				return fmt.Errorf("fixservice: job %s ended %s", jobID, st.Status)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
	return fmt.Errorf("fixservice: job %s did not finish within %d polls", jobID, maxPolls)
}

// fetchResult reads the patch (delete-on-read on the server).
func fetchResult(ctx context.Context, cfg Config, jobID string) (Result, error) {
	resultURL := fmt.Sprintf("%s/v1/fix/jobs/%s/result", cfg.base(), url.PathEscape(jobID))
	req, err := newRequest(ctx, http.MethodGet, resultURL, cfg.Token, nil)
	if err != nil {
		return Result{}, err
	}
	var res Result
	if err := doJSON(req, &res); err != nil {
		return Result{}, err
	}
	return res, nil
}

// idempotencyKey is a stable key so a retried submit reuses the same job.
func idempotencyKey(req Request) string {
	sum := sha256.Sum256([]byte(req.Filename + "\n" + req.FileContent))
	return hex.EncodeToString(sum[:])
}

// newRequest builds a bearer-authenticated request.
func newRequest(ctx context.Context, method, url, token string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

// doJSON executes the request, requires a 2xx, and decodes JSON into out.
func doJSON(req *http.Request, out interface{}) error {
	resp, err := (&http.Client{Timeout: requestTimeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("fixservice: %s %s -> HTTP %d", req.Method, req.URL.Path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	// Cap the body so a compromised/MITM'd service can't OOM us (patched_content
	// is written to disk downstream).
	return json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out)
}

// ValidateEndpoint refuses plaintext HTTP to a non-loopback host: the scoped
// token and the located file/prompt would otherwise cross the network in
// cleartext. Exported so the whole flow (locate + fix) can gate on it up front.
func ValidateEndpoint(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("fixservice: invalid fix-url: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("fixservice: refusing plaintext http to non-loopback host %q — use https", u.Host)
}

// isLoopback reports whether host is localhost or a loopback IP.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
