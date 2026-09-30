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

// healthScoreServer mocks the endpoints the health-score gate talks to and
// counts requests per path, so tests can assert what was (not) called.
type healthScoreServer struct {
	statusCode int    // HTTP status for knoxiq_scan/status; 0 means 200
	sastStatus int    // sast_status in the knoxiq_scan/status body
	statusSeq  []int  // if set, successive sast_status values (last one repeats)
	auditCode  int    // HTTP status for health_score_audit; 0 means 200
	auditJSON  string // health_score_audit body
	cicdJSON   string // cicd_analyses body

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
	// current_score is deliberately different from the health_score endpoint's
	// 34, so a test can tell which of the two responses a score came from.
	auditRecalculated = `{"current_score":{"score":47},"audit_trail":[` +
		`{"event_type":"sast_completed","knoxiq_ran":false,"score":34},` +
		`{"event_type":"sast_completed","knoxiq_ran":true,"score":47}]}`
	auditNotRecalculated = `{"current_score":{"score":34},"audit_trail":[` +
		`{"event_type":"sast_completed","knoxiq_ran":false,"score":34}]}`
)

// withGrace shrinks knoxIQHealthScoreGrace for one test.
func withGrace(t *testing.T, d time.Duration) {
	t.Helper()
	old := knoxIQHealthScoreGrace
	knoxIQHealthScoreGrace = d
	t.Cleanup(func() { knoxIQHealthScoreGrace = old })
}

// TestAwaitKnoxIQHealthScore_PendingThenRecalculated is the CI case: triage is
// still running when the static scan finishes, so the gate must wait for it
// and report the score it replaced.
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

// TestAwaitKnoxIQHealthScore_AlreadyCompleted checks a file whose triage
// finished earlier: its stored score may already be the adjusted one, so it
// must not be labelled "before triage".
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

// TestAwaitKnoxIQHealthScore_NotAvailable is the "no KnoxIQ" guarantee: an org
// without KnoxIQ must get today's health-score flow with no extra calls.
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

// TestAwaitKnoxIQHealthScore_NeverRecalculated covers triage that completed
// without the backend ever writing the KnoxIQ-adjusted score (seen on staging):
// fall back to the current score with a warning instead of waiting forever.
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

// TestKnoxIQHealthScoreReady_BackendWithoutAudit checks an older backend with
// no audit endpoint fails fast rather than burning the whole grace period.
func TestKnoxIQHealthScoreReady_BackendWithoutAudit(t *testing.T) {
	srv := &healthScoreServer{auditCode: 404}
	client, teardown := srv.start(t)
	defer teardown()

	start := time.Now()
	_, ready := knoxIQHealthScoreReady(context.Background(), client, 1, time.Now().Add(time.Minute))

	assert.False(t, ready)
	assert.Less(t, time.Since(start), 2*time.Second)
}

// TestKnoxIQHealthScoreReady_NoCurrentScore guards the nil current_score case
// (no recalculations recorded): treated as not ready, never a nil dereference.
func TestKnoxIQHealthScoreReady_NoCurrentScore(t *testing.T) {
	srv := &healthScoreServer{auditJSON: `{"current_score":null,"audit_trail":[` +
		`{"event_type":"sast_completed","knoxiq_ran":true,"score":47}]}`}
	client, teardown := srv.start(t)
	defer teardown()

	_, ready := knoxIQHealthScoreReady(context.Background(), client, 1, time.Now())

	assert.False(t, ready)
}

// TestCountLikelihoodOffenders_UsesCompletedTriage checks the likelihood gate
// reads the triage the health-score flow already waited for, instead of
// polling KnoxIQ a second time.
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
