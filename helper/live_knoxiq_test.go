package helper

import (
	"context"
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/appknox/appknox-go/appknox"
)

// TestLive_KnoxIQInputs shows exactly what the fixer is handed for a real
// analysis, so "the remediation comes from KnoxIQ" is something we observe
// rather than infer.
//
// Skipped unless APPKNOX_LIVE=1, so it never runs in CI. Needs:
//
//	APPKNOX_LIVE=1 APPKNOX_API_HOST=https://host/ APPKNOX_ACCESS_TOKEN=<api/v2 token> \
//	APPKNOX_LIVE_ANALYSIS_ID=11829 go test ./helper/ -run TestLive_KnoxIQInputs -v
func TestLive_KnoxIQInputs(t *testing.T) {
	client, analysisID := liveClient(t)

	findings, err := fixableKnoxIQFindings(context.Background(), client, analysisID)
	if err != nil {
		t.Fatalf("KnoxIQ unreachable (this must fail the run, never fall back): %v", err)
	}
	t.Logf("analysis %d -> %d fixable KnoxIQ finding(s)", analysisID, len(findings))

	inputs := knoxIQInputs(findings, "live-check")
	for _, f := range findings {
		t.Logf("  %s kb_id=%s verification=%d",
			f.FindingID, kbID(f), len(f.Remediation.Verification))
	}
	t.Logf("class hints : %v", inputs.ClassHints)
	t.Logf("criteria    : %d", len(inputs.Criteria))
	t.Logf("REMEDIATION HANDED TO THE FIXER:\n%s", inputs.Remediation)

	if inputs.Remediation == "" {
		t.Error("no remediation assembled from KnoxIQ")
	}
}

// liveClient builds a client from the environment, skipping when the live
// credentials are absent.
func liveClient(t *testing.T) (*appknox.Client, int) {
	t.Helper()
	if os.Getenv("APPKNOX_LIVE") != "1" {
		t.Skip("set APPKNOX_LIVE=1 to run against a real Appknox host")
	}
	host, token := os.Getenv("APPKNOX_API_HOST"), os.Getenv("APPKNOX_ACCESS_TOKEN")
	if host == "" || token == "" {
		t.Skip("APPKNOX_API_HOST and APPKNOX_ACCESS_TOKEN are required")
	}
	analysisID, err := strconv.Atoi(os.Getenv("APPKNOX_LIVE_ANALYSIS_ID"))
	if err != nil {
		t.Skip("set APPKNOX_LIVE_ANALYSIS_ID to a real analysis id")
	}

	client, err := appknox.NewClient(token)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	base, err := url.Parse(host)
	if err != nil {
		t.Fatalf("bad APPKNOX_API_HOST: %v", err)
	}
	client.BaseURL = base
	return client, analysisID
}

// kbID reports the knowledge-base entry a finding's remediation came from.
func kbID(f *appknox.KnoxIQFinding) string {
	if f.Remediation == nil || f.Remediation.Source == nil {
		return "-"
	}
	if v, ok := f.Remediation.Source["kb_id"].(string); ok {
		return v
	}
	return "-"
}
