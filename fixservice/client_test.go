package fixservice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// fixServer stands in for the hosted fix service: submit -> poll -> result.
func fixServer(t *testing.T, statuses []string, result Result) (*httptest.Server, *[]string) {
	t.Helper()
	seen := &[]string{}
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/fix/jobs":
			require.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
			require.NotEmpty(t, r.Header.Get("Idempotency-Key"))
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"job_id": "J1", "status": "queued"})
		case r.URL.Path == "/v1/fix/jobs/J1":
			s := statuses[i]
			if i < len(statuses)-1 {
				i++
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": s})
		case r.URL.Path == "/v1/fix/jobs/J1/result":
			_ = json.NewEncoder(w).Encode(result)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv, seen
}

func TestSubmitAndAwait_Success(t *testing.T) {
	srv, seen := fixServer(t, []string{"running", "succeeded"},
		Result{Changed: true, PatchedContent: "fixed", UnifiedDiff: "+fixed", Confidence: 0.9})
	defer srv.Close()

	res, err := SubmitAndAwait(context.Background(),
		Config{URL: srv.URL, Token: "tok", PollInterval: 1},
		Request{Filename: "A.java", FileContent: "c", Remediation: "r"})
	require.NoError(t, err)
	require.True(t, res.Changed)
	require.Equal(t, "fixed", res.PatchedContent)
	require.InDelta(t, 0.9, res.Confidence, 0.001)
	require.Contains(t, *seen, "POST /v1/fix/jobs")
	require.Contains(t, *seen, "GET /v1/fix/jobs/J1/result")
}

func TestSubmitAndAwait_FailedJob(t *testing.T) {
	srv, _ := fixServer(t, []string{"failed"}, Result{})
	defer srv.Close()
	_, err := SubmitAndAwait(context.Background(),
		Config{URL: srv.URL, Token: "tok", PollInterval: 1},
		Request{Filename: "A.java", FileContent: "c", Remediation: "r"})
	require.Error(t, err)
}

func TestSubmitAndAwait_PollTimeout(t *testing.T) {
	srv, _ := fixServer(t, []string{"running"}, Result{})
	defer srv.Close()
	_, err := SubmitAndAwait(context.Background(),
		Config{URL: srv.URL, Token: "tok", PollInterval: 1, MaxPolls: 2},
		Request{Filename: "A.java", FileContent: "c", Remediation: "r"})
	require.Error(t, err)
}

func TestSubmitAndAwait_SubmitErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, err := SubmitAndAwait(context.Background(), Config{URL: srv.URL, Token: "bad"},
		Request{Filename: "A.java", FileContent: "c", Remediation: "r"})
	require.Error(t, err)
}

func TestValidateEndpoint(t *testing.T) {
	require.NoError(t, ValidateEndpoint("http://localhost:8100"))
	require.NoError(t, ValidateEndpoint("http://127.0.0.1:8100"))
	require.NoError(t, ValidateEndpoint("https://fix.appknox.com"))
	require.Error(t, ValidateEndpoint("http://fix.appknox.com")) // plaintext to remote
	require.Error(t, ValidateEndpoint("http://192.168.1.10:8100"))
}

func TestSubmitAndAwait_RejectsPlaintextRemote(t *testing.T) {
	_, err := SubmitAndAwait(context.Background(),
		Config{URL: "http://evil.example.com", Token: "tok"},
		Request{Filename: "A.java", FileContent: "c", Remediation: "r"})
	require.Error(t, err)
}

func TestIdempotencyKey_StableAndContentSensitive(t *testing.T) {
	a := Request{Filename: "A.java", FileContent: "x"}
	require.Equal(t, idempotencyKey(a), idempotencyKey(a))
	require.NotEqual(t, idempotencyKey(a), idempotencyKey(Request{Filename: "A.java", FileContent: "y"}))
}
