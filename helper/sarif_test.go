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

func TestFilterAnalysesForSARIF(t *testing.T) {
	analyses := []*appknox.Analysis{
		{ID: 1, ComputedRisk: enums.Risk.High},
		{ID: 2, ComputedRisk: enums.Risk.Low},
		{ID: 3, ComputedRisk: enums.Risk.High},
	}
	got := filterAnalysesForSARIF(analyses, int(enums.Risk.Medium), map[int]bool{3: true})
	assert.Len(t, got, 1)
	assert.Equal(t, 1, got[0].ID)
}

func TestSarifPropertiesFor_NoTriageData(t *testing.T) {
	assert.Nil(t, sarifPropertiesFor(&appknox.KnoxIQCICDAnalysis{ID: 1}))
}

func TestSarifPropertiesFor_WithTriageData(t *testing.T) {
	score := 6.5
	high := enums.Exploitability.High
	props := sarifPropertiesFor(&appknox.KnoxIQCICDAnalysis{
		ID: 2, ExploitabilityScore: &score, ExploitabilityLikelihood: &high,
	})
	if assert.NotNil(t, props) {
		assert.Equal(t, &score, props.AEISScore)
		assert.Equal(t, "High", props.ExploitLikelihood)
	}
}

func sarifTestServer(t *testing.T, handler http.HandlerFunc) (*appknox.Client, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
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

// TestKnoxIQSARIFOverlay_Available covers the Req 2/3 parity path: needs-review
// rows are excluded, and a properties entry is attached only for a row that
// actually has AEIS score/exploit likelihood data.
func TestKnoxIQSARIFOverlay_Available(t *testing.T) {
	client, teardown := sarifTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/knoxiq/file/1/knoxiq_scan/status":
			fmt.Fprint(w, `{"id":1,"sast_status":4,"dast_status":0}`)
		case "/api/knoxiq/file/1/cicd/analyses":
			fmt.Fprint(w, `{"count":2,"results":[`+
				`{"id":10,"computed_risk":3,"exploitability_score":8.2,"exploitability_likelihood":4,"needs_review":false},`+
				`{"id":11,"computed_risk":4,"needs_review":true}]}`)
		default:
			http.NotFound(w, r)
		}
	})
	defer teardown()
	viper.Set("include-needs-review", false)
	budget := NewScanBudget(time.Minute, time.Minute)

	var properties map[int]*appknox.ResultProperties
	var excluded map[int]bool
	captureOutput(func() {
		properties, excluded = knoxIQSARIFOverlay(context.Background(), client, 1, budget)
	})

	assert.True(t, excluded[11])
	assert.False(t, excluded[10])
	if assert.Contains(t, properties, 10) {
		assert.Equal(t, "High", properties[10].ExploitLikelihood)
	}
	assert.NotContains(t, properties, 11)
}

func TestKnoxIQSARIFOverlay_NotAvailable(t *testing.T) {
	client, teardown := sarifTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	defer teardown()
	budget := NewScanBudget(time.Minute, time.Minute)

	properties, excluded := knoxIQSARIFOverlay(context.Background(), client, 1, budget)
	assert.Empty(t, properties)
	assert.Empty(t, excluded)
}
