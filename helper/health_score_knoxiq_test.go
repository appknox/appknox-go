package helper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

type healthScoreServer struct {
	statusCode int
	sastStatus int
	statusSeq  []int
	auditCode  int
	auditJSON  string
	cicdJSON   string

	mu       sync.Mutex
	requests map[string]int
}

func (s *healthScoreServer) hits(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[path]
}

func (s *healthScoreServer) start(t *testing.T) (*appknox.Client, func()) {
	t.Helper()
	s.requests = map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests[r.URL.Path]++
		n := s.requests[r.URL.Path]
		s.mu.Unlock()
		switch r.URL.Path {
		case "/api/knoxiq/file/1/knoxiq_scan/status":
			if s.statusCode != 0 {
				w.WriteHeader(s.statusCode)
				return
			}
			status := s.sastStatus
			if len(s.statusSeq) > 0 {
				status = s.statusSeq[min(n, len(s.statusSeq))-1]
			}
			fmt.Fprintf(w, `{"id":1,"sast_status":%d,"dast_status":0}`, status)
		case "/api/v3/files/1/health_score":
			fmt.Fprint(w, `{"health_score":34}`)
		case "/api/v3/files/1/health_score_audit":
			if s.auditCode != 0 {
				w.WriteHeader(s.auditCode)
				return
			}
			fmt.Fprint(w, s.auditJSON)
		case "/api/knoxiq/file/1/cicd_analyses":
			fmt.Fprint(w, s.cicdJSON)
		default:
			http.NotFound(w, r)
		}
	}))
	oldHost := viper.GetString("host")
	oldToken := viper.GetString("access-token")
	viper.Set("access-token", "FAKE-TOKEN")
	viper.Set("host", server.URL+"/")
	teardown := func() {
		viper.Set("access-token", oldToken)
		viper.Set("host", oldHost)
		server.Close()
	}
	return getClient(), teardown
}

const (
	// Differs from the health_score endpoint's 34 so tests can tell the sources apart.
	auditRecalculated = `{"current_score":{"score":47},"audit_trail":[` +
		`{"event_type":"sast_completed","knoxiq_ran":false,"score":34},` +
		`{"event_type":"sast_completed","knoxiq_ran":true,"score":47}]}`
	auditNotRecalculated = `{"current_score":{"score":34},"audit_trail":[` +
		`{"event_type":"sast_completed","knoxiq_ran":false,"score":34}]}`
)

func withGrace(t *testing.T, d time.Duration) {
	t.Helper()
	old := knoxIQHealthScoreGrace
	knoxIQHealthScoreGrace = d
	t.Cleanup(func() { knoxIQHealthScoreGrace = old })
}

func TestAwaitKnoxIQHealthScore_PendingThenRecalculated(t *testing.T) {
	srv := &healthScoreServer{statusSeq: []int{2, 4}, auditJSON: auditRecalculated}
	client, teardown := srv.start(t)
	defer teardown()

	var triage healthScoreTriage
	out := captureOutput(func() {
		triage = awaitKnoxIQHealthScore(context.Background(), client, 1, NewScanBudget(time.Minute, time.Minute))
	})

	assert.Equal(t, healthScoreTriage{available: true, completed: true, scoreReady: true, score: 47}, triage)
	assert.Contains(t, out, "Health score before KnoxIQ triage: 34")
	assert.Equal(t, 1, srv.hits("/api/v3/files/1/health_score"),
		"only the pre-triage score is fetched; the final one comes from the audit response")
}

func TestAwaitKnoxIQHealthScore_AlreadyCompleted(t *testing.T) {
	srv := &healthScoreServer{sastStatus: 4, auditJSON: auditRecalculated}
	client, teardown := srv.start(t)
	defer teardown()

	var triage healthScoreTriage
	out := captureOutput(func() {
		triage = awaitKnoxIQHealthScore(context.Background(), client, 1, NewScanBudget(time.Minute, time.Minute))
	})

	assert.Equal(t, healthScoreTriage{available: true, completed: true, scoreReady: true, score: 47}, triage)
	assert.NotContains(t, out, "before KnoxIQ triage")
	assert.Zero(t, srv.hits("/api/v3/files/1/health_score"))
}

func TestAwaitKnoxIQHealthScore_NotAvailable(t *testing.T) {
	srv := &healthScoreServer{statusCode: 403}
	client, teardown := srv.start(t)
	defer teardown()

	var triage healthScoreTriage
	out := captureOutput(func() {
		triage = awaitKnoxIQHealthScore(context.Background(), client, 1, NewScanBudget(time.Minute, time.Minute))
	})

	assert.Equal(t, healthScoreTriage{}, triage)
	assert.Empty(t, out)
	assert.Zero(t, srv.hits("/api/v3/files/1/health_score"))
	assert.Zero(t, srv.hits("/api/v3/files/1/health_score_audit"))
}

func TestAwaitKnoxIQHealthScore_TimesOut(t *testing.T) {
	srv := &healthScoreServer{sastStatus: 3, auditJSON: auditRecalculated}
	client, teardown := srv.start(t)
	defer teardown()
	expired := ScanBudget{Start: time.Now().Add(-time.Hour), SastTimeout: time.Minute, KnoxIQTimeout: time.Minute}

	var triage healthScoreTriage
	errOut := captureStderr(func() {
		captureOutput(func() {
			triage = awaitKnoxIQHealthScore(context.Background(), client, 1, expired)
		})
	})

	assert.Equal(t, healthScoreTriage{available: true}, triage)
	assert.Contains(t, errOut, "KnoxIQ did not complete")
	assert.Zero(t, srv.hits("/api/v3/files/1/health_score_audit"))
}

func TestAwaitKnoxIQHealthScore_NeverRecalculated(t *testing.T) {
	withGrace(t, 0)
	srv := &healthScoreServer{sastStatus: 4, auditJSON: auditNotRecalculated}
	client, teardown := srv.start(t)
	defer teardown()

	var triage healthScoreTriage
	errOut := captureStderr(func() {
		captureOutput(func() {
			triage = awaitKnoxIQHealthScore(context.Background(), client, 1, NewScanBudget(time.Minute, time.Minute))
		})
	})

	assert.Equal(t, healthScoreTriage{available: true, completed: true}, triage)
	assert.Contains(t, errOut, "has not been recalculated")
}

func TestKnoxIQHealthScoreReady_BackendWithoutAudit(t *testing.T) {
	srv := &healthScoreServer{auditCode: 404}
	client, teardown := srv.start(t)
	defer teardown()

	start := time.Now()
	_, ready := knoxIQHealthScoreReady(context.Background(), client, 1, time.Now().Add(time.Minute))

	assert.False(t, ready)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestKnoxIQHealthScoreReady_NoCurrentScore(t *testing.T) {
	srv := &healthScoreServer{auditJSON: `{"current_score":null,"audit_trail":[` +
		`{"event_type":"sast_completed","knoxiq_ran":true,"score":47}]}`}
	client, teardown := srv.start(t)
	defer teardown()

	_, ready := knoxIQHealthScoreReady(context.Background(), client, 1, time.Now())

	assert.False(t, ready)
}

func TestCountLikelihoodOffenders_UsesCompletedTriage(t *testing.T) {
	old := viper.GetBool(ConfigKeyIncludeNeedsReview)
	viper.Set(ConfigKeyIncludeNeedsReview, false)
	defer viper.Set(ConfigKeyIncludeNeedsReview, old)
	srv := &healthScoreServer{cicdJSON: `{"count":3,"results":[` +
		`{"id":10,"computed_risk":3,"exploitability_likelihood":4,"needs_review":false},` +
		`{"id":11,"computed_risk":3,"exploitability_likelihood":4,"needs_review":true},` +
		`{"id":12,"computed_risk":2,"exploitability_likelihood":2,"needs_review":false}]}`}
	client, teardown := srv.start(t)
	defer teardown()
	policy := CiPolicy{RiskThreshold: -1, LikelihoodThreshold: 4, HealthScoreThreshold: 40}

	count := countLikelihoodOffenders(context.Background(), client, 1, policy,
		healthScoreTriage{available: true, completed: true})

	assert.Equal(t, 1, count, "only the counted (non-needs-review) High row breaches")
	assert.Zero(t, srv.hits("/api/knoxiq/file/1/knoxiq_scan/status"))
}

func TestCountLikelihoodOffenders_SkipsIncompleteTriage(t *testing.T) {
	srv := &healthScoreServer{}
	client, teardown := srv.start(t)
	defer teardown()
	policy := CiPolicy{RiskThreshold: -1, LikelihoodThreshold: 4, HealthScoreThreshold: 40}

	var count int
	errOut := captureStderr(func() {
		count = countLikelihoodOffenders(context.Background(), client, 1, policy,
			healthScoreTriage{available: true})
	})

	assert.Zero(t, count)
	assert.Contains(t, errOut, "skipping exploit-likelihood gate")
	assert.Zero(t, srv.hits("/api/knoxiq/file/1/cicd_analyses"))
}

func TestBuildHealthScoreVerdict(t *testing.T) {
	healthOnly := CiPolicy{RiskThreshold: -1, LikelihoodThreshold: -1, HealthScoreThreshold: 60}
	withLikelihood := CiPolicy{RiskThreshold: -1, LikelihoodThreshold: 4, HealthScoreThreshold: 60}

	tests := []struct {
		name            string
		policy          CiPolicy
		score           int
		likelihoodCount int
		afterTriage     bool
		want            healthScoreVerdict
	}{
		{
			name: "pass, no KnoxIQ (original wording)", policy: healthOnly, score: 85,
			want: healthScoreVerdict{stdout: []string{
				"\nHealth score 85 is greater than or equal to threshold 60. Build passed.\n"}},
		},
		{
			name: "fail, no KnoxIQ (original wording)", policy: healthOnly, score: 50,
			want: healthScoreVerdict{failed: true, stderr: []string{
				"Health score 50 is below the threshold 60. Build failed.\n"}},
		},
		{
			name: "pass after triage", policy: healthOnly, score: 85, afterTriage: true,
			want: healthScoreVerdict{stdout: []string{
				"\nHealth score 85 (after KnoxIQ triage) is greater than or equal to threshold 60. Build passed.\n"}},
		},
		{
			name: "fail after triage", policy: healthOnly, score: 50, afterTriage: true,
			want: healthScoreVerdict{failed: true, stderr: []string{
				"Health score 50 (after KnoxIQ triage) is below the threshold 60. Build failed.\n"}},
		},
		{
			name: "score passes, likelihood fails", policy: withLikelihood, score: 85, likelihoodCount: 2, afterTriage: true,
			want: healthScoreVerdict{failed: true,
				stdout: []string{"\nHealth score 85 (after KnoxIQ triage) is greater than or equal to threshold 60.\n"},
				stderr: []string{"Found 2 vulnerabilities with exploit likelihood >= High", "Build failed."}},
		},
		{
			name: "score and likelihood both fail", policy: withLikelihood, score: 50, likelihoodCount: 2, afterTriage: true,
			want: healthScoreVerdict{failed: true, stderr: []string{
				"Health score 50 (after KnoxIQ triage) is below the threshold 60.",
				"Found 2 vulnerabilities with exploit likelihood >= High",
				"Build failed."}},
		},
		{
			name: "likelihood gate on, nothing breaches", policy: withLikelihood, score: 85, afterTriage: true,
			want: healthScoreVerdict{stdout: []string{
				"\nHealth score 85 (after KnoxIQ triage) is greater than or equal to threshold 60. Build passed.\n"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildHealthScoreVerdict(tt.policy, tt.score, tt.likelihoodCount, tt.afterTriage)
			assert.Equal(t, tt.want, got)
		})
	}
}
