package helper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func cicdRow(id, risk int, needsReview bool) *appknox.KnoxIQCICDAnalysis {
	return &appknox.KnoxIQCICDAnalysis{
		ID:           id,
		ComputedRisk: enums.RiskType(risk),
		NeedsReview:  needsReview,
	}
}

func TestPartitionNeedsReview_ExcludeByDefault(t *testing.T) {
	rows := []*appknox.KnoxIQCICDAnalysis{
		cicdRow(1, 3, false),
		cicdRow(2, 4, true),
	}
	counted, needsReview := partitionNeedsReview(rows, false)
	assert.Len(t, counted, 1)
	assert.Equal(t, 1, counted[0].ID)
	assert.Len(t, needsReview, 1)
	assert.Equal(t, 2, needsReview[0].ID)
}

func TestPartitionNeedsReview_IncludeKeepsAll(t *testing.T) {
	rows := []*appknox.KnoxIQCICDAnalysis{
		cicdRow(1, 3, false),
		cicdRow(2, 4, true),
	}
	counted, needsReview := partitionNeedsReview(rows, true)
	assert.Len(t, counted, 2)
	assert.Len(t, needsReview, 0)
}

func TestFilterCICDByLikelihood(t *testing.T) {
	low := enums.Exploitability.Low
	high := enums.Exploitability.High
	rows := []*appknox.KnoxIQCICDAnalysis{
		{ID: 1, ExploitabilityLikelihood: nil},
		{ID: 2, ExploitabilityLikelihood: &low},
		{ID: 3, ExploitabilityLikelihood: &high},
	}
	// threshold medium (3) -> only High
	got := filterCICDByLikelihood(rows, 3)
	assert.Len(t, got, 1)
	assert.Equal(t, 3, got[0].ID)
	// threshold low (2) -> Low and High; nil is never counted
	assert.Len(t, filterCICDByLikelihood(rows, 2), 2)
}

func TestUnionCICD(t *testing.T) {
	a := []*appknox.KnoxIQCICDAnalysis{{ID: 1}, {ID: 2}}
	b := []*appknox.KnoxIQCICDAnalysis{{ID: 2}, {ID: 3}}
	got := unionCICD(a, b)
	assert.Len(t, got, 3) // 1, 2, 3 with the shared ID 2 de-duplicated
}

func TestFilterCICDByRisk(t *testing.T) {
	rows := []*appknox.KnoxIQCICDAnalysis{
		cicdRow(1, 1, false),
		cicdRow(2, 3, false),
		cicdRow(3, 4, false),
	}
	vulnerable := filterCICDByRisk(rows, 3)
	assert.Len(t, vulnerable, 2)
	assert.Equal(t, 2, vulnerable[0].ID)
	assert.Equal(t, 3, vulnerable[1].ID)
}

func TestAeisString(t *testing.T) {
	assert.Equal(t, "N/A", aeisString(nil))
	score := 7.5
	assert.Equal(t, "7.5", aeisString(&score))
}

func TestLikelihoodString(t *testing.T) {
	assert.Equal(t, "N/A", likelihoodString(nil))
	high := enums.Exploitability.High
	assert.Equal(t, "High", likelihoodString(&high))
}

func knoxIQStatusServer(t *testing.T, sastStatus int) (*appknox.Client, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/knoxiq/file/1/knoxiq_scan/status" {
			fmt.Fprintf(w, `{"id":1,"sast_status":%d,"dast_status":0}`, sastStatus)
			return
		}
		http.NotFound(w, r)
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

func TestWaitForKnoxIQ_Completed(t *testing.T) {
	client, teardown := knoxIQStatusServer(t, int(enums.KnoxIQStatusCompleted))
	defer teardown()
	captureOutput(func() {
		assert.True(t, waitForKnoxIQ(context.Background(), client, 1, time.Now().Add(time.Minute)))
	})
}

func TestWaitForKnoxIQ_Errored(t *testing.T) {
	client, teardown := knoxIQStatusServer(t, int(enums.KnoxIQStatusErrored))
	defer teardown()
	captureOutput(func() {
		assert.False(t, waitForKnoxIQ(context.Background(), client, 1, time.Now().Add(time.Minute)))
	})
}

// TestWarnLikelihoodUnavailable_RestoresRiskGate is the fail-open regression:
// a likelihood-only cicheck (RiskThreshold left at -1 by parseCiPolicy) against
// a file with no KnoxIQ triage used to leave zero active gates and pass having
// checked nothing. It must fall back to the default risk gate instead.
func TestWarnLikelihoodUnavailable_RestoresRiskGate(t *testing.T) {
	policy := CiPolicy{RiskThreshold: -1, LikelihoodThreshold: int(enums.Exploitability.High)}
	warnLikelihoodUnavailable(&policy)
	assert.Equal(t, int(enums.Risk.Low), policy.RiskThreshold)
}

func TestWarnLikelihoodUnavailable_KeepsExplicitRiskGate(t *testing.T) {
	policy := CiPolicy{RiskThreshold: int(enums.Risk.High), LikelihoodThreshold: int(enums.Exploitability.High)}
	warnLikelihoodUnavailable(&policy)
	assert.Equal(t, int(enums.Risk.High), policy.RiskThreshold)
}

func TestWarnLikelihoodUnavailable_NoOpWithoutLikelihoodGate(t *testing.T) {
	policy := CiPolicy{RiskThreshold: -1, LikelihoodThreshold: -1}
	warnLikelihoodUnavailable(&policy)
	assert.Equal(t, -1, policy.RiskThreshold)
}

func TestPrintActiveGates(t *testing.T) {
	tests := []struct {
		name   string
		policy CiPolicy
		want   string
	}{
		{"no gates", CiPolicy{RiskThreshold: -1, LikelihoodThreshold: -1}, "Active gates: none"},
		{"risk only", CiPolicy{RiskThreshold: int(enums.Risk.Low), LikelihoodThreshold: -1}, "Active gates: risk >= Low"},
		{"likelihood only", CiPolicy{RiskThreshold: -1, LikelihoodThreshold: int(enums.Exploitability.High)}, "Active gates: exploit likelihood >= High"},
		{"both", CiPolicy{RiskThreshold: int(enums.Risk.Low), LikelihoodThreshold: int(enums.Exploitability.High)}, "Active gates: risk >= Low, exploit likelihood >= High"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := captureOutput(func() { printActiveGates(tt.policy) })
			assert.Contains(t, out, tt.want)
		})
	}
}
