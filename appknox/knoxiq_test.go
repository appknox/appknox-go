package appknox

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// liveFindingJSON is trimmed from a real response for analysis 11829 (Weak PRNG)
// on the KnoxIQ UAT host, so parsing is exercised against the production shape
// rather than an invented one. Note the code identifiers in `verification` are
// NOT backticked -- live output has no backticks, and assuming otherwise has
// already cost us one wrong "criteria satisfied" verdict.
const liveFindingJSON = `{
  "count": 1,
  "results": [
    {
      "finding_id": "F-1",
      "title": "Activity := Lcom/appknox/mfva/MainActivity$3;",
      "description": "Weak PRNG in an onClick handler.",
      "remediation": {
        "remediation": "The application uses Math.random() ... replace it with SecureRandom.",
        "steps": ["Remove Insecure Random Number Generation", "Import SecureRandom"],
        "code_examples": ["import java.security.SecureRandom;"],
        "references": ["https://cwe.mitre.org/data/definitions/338.html"],
        "verification": [
          "Confirm that all Math.random() calls have been replaced with SecureRandom.nextInt()",
          "Run static analysis to confirm no remaining java.util.Random imports in MainActivity.java"
        ],
        "source": {"source_type": "KB", "kb_id": "v_android_weak_prng", "confidence": 0.95}
      },
      "validation": {
        "verdict": "TRUE_POSITIVE",
        "is_valid": true,
        "confidence": 0.9,
        "confidence_label": "HIGH",
        "finding_summary": "first-party app code uses Math.random()",
        "evidence": ["The class is APP_OWNED"],
        "reasoning": "APP_OWNED confirmed",
        "is_third_party": false,
        "library_origin": null
      },
      "developer_prompt": "Fix the weak PRNG..."
    }
  ]
}`

// withFastRetries removes the backoff sleep so retry tests stay quick, and
// restores the production values afterwards.
func withFastRetries(t *testing.T) {
	t.Helper()
	prevDelay, prevAttempts := knoxiqRetryBaseDelay, knoxiqMaxAttempts
	knoxiqRetryBaseDelay = time.Millisecond
	t.Cleanup(func() {
		knoxiqRetryBaseDelay, knoxiqMaxAttempts = prevDelay, prevAttempts
	})
}

func TestKnoxIQ_ListByAnalysis_parsesLivePayload(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/analyses/11829/findings", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, liveFindingJSON)
	})

	findings, err := client.KnoxIQ.ListByAnalysis(context.Background(), 11829)
	if err != nil {
		t.Fatalf("ListByAnalysis returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.FindingID != "F-1" {
		t.Errorf("FindingID = %q, want F-1", f.FindingID)
	}
	if f.Remediation == nil || f.Remediation.Source["kb_id"] != "v_android_weak_prng" {
		t.Errorf("kb_id not parsed: %+v", f.Remediation)
	}
	if f.Validation == nil || f.Validation.Verdict != "TRUE_POSITIVE" {
		t.Errorf("verdict not parsed: %+v", f.Validation)
	}
	if f.Validation.IsThirdParty == nil || *f.Validation.IsThirdParty {
		t.Errorf("IsThirdParty = %v, want pointer to false", f.Validation.IsThirdParty)
	}
}

// The verification steps are the criteria a generated patch gets checked
// against; losing them silently is the bug this whole change exists to fix.
func TestKnoxIQ_ListByAnalysis_parsesVerificationCriteria(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/analyses/11829/findings", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, liveFindingJSON)
	})

	findings, err := client.KnoxIQ.ListByAnalysis(context.Background(), 11829)
	if err != nil {
		t.Fatalf("ListByAnalysis returned error: %v", err)
	}
	got := findings[0].Remediation.Verification
	if len(got) != 2 {
		t.Fatalf("got %d verification steps, want 2: %v", len(got), got)
	}
	if got[0] != "Confirm that all Math.random() calls have been replaced with SecureRandom.nextInt()" {
		t.Errorf("unexpected first criterion: %q", got[0])
	}
}

// A finding analysed before the storage layer stopped dropping the field simply
// has no verification. That must parse cleanly -- the caller decides what an
// empty criteria list means, and it must never mean "passed".
func TestKnoxIQ_ListByAnalysis_absentVerificationIsEmpty(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/analyses/1/findings", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"count":1,"results":[{"finding_id":"F-0","remediation":{"remediation":"x"}}]}`)
	})

	findings, err := client.KnoxIQ.ListByAnalysis(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListByAnalysis returned error: %v", err)
	}
	if len(findings[0].Remediation.Verification) != 0 {
		t.Errorf("want no verification steps, got %v", findings[0].Remediation.Verification)
	}
}

func TestKnoxIQ_ListByAnalysis_emptyWhenNotProcessed(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/analyses/7/findings", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"count":0,"results":[]}`)
	})

	findings, err := client.KnoxIQ.ListByAnalysis(context.Background(), 7)
	if err != nil {
		t.Fatalf("reachable-but-empty must not be an error, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

// A credential problem is not transient. Retrying it wastes time and muddies
// the error, so 401 must fail on the first attempt.
func TestKnoxIQ_ListByAnalysis_401FailsImmediately(t *testing.T) {
	withFastRetries(t)
	client, mux, _, teardown := setup()
	defer teardown()

	var attempts int
	mux.HandleFunc("/api/knoxiq/analyses/11829/findings", func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"detail":"Invalid token."}`)
	})

	_, err := client.KnoxIQ.ListByAnalysis(context.Background(), 11829)
	if err == nil {
		t.Fatal("want an error for 401")
	}
	if attempts != 1 {
		t.Errorf("401 was retried %d times; want exactly 1 attempt", attempts)
	}
}

// mycroft gates this route on the org's KnoxIQ entitlement
// (KnoxIQPermission -> guaranteed_ai_feature.knoxiq), so a 403 means the
// ACCOUNT lacks the feature, not that the token is wrong. Reporting a token
// problem here sends a customer off rotating credentials over a licensing gap.
func TestKnoxIQ_ListByAnalysis_403ReportsEntitlementNotToken(t *testing.T) {
	withFastRetries(t)
	client, mux, _, teardown := setup()
	defer teardown()

	var attempts int
	mux.HandleFunc("/api/knoxiq/analyses/11829/findings", func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusForbidden)
	})

	_, err := client.KnoxIQ.ListByAnalysis(context.Background(), 11829)
	if err == nil {
		t.Fatal("want an error for 403")
	}
	if !strings.Contains(err.Error(), "not entitled") {
		t.Errorf("403 must explain the entitlement gap, got: %v", err)
	}
	if strings.Contains(err.Error(), "keyId") {
		t.Errorf("403 must NOT blame the token format, got: %v", err)
	}
	if attempts != 1 {
		t.Errorf("403 is not transient; want 1 attempt, got %d", attempts)
	}
}

func TestKnoxIQ_ListByAnalysis_retriesServerErrorsThenSucceeds(t *testing.T) {
	withFastRetries(t)
	client, mux, _, teardown := setup()
	defer teardown()

	var attempts int
	mux.HandleFunc("/api/knoxiq/analyses/11829/findings", func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, liveFindingJSON)
	})

	findings, err := client.KnoxIQ.ListByAnalysis(context.Background(), 11829)
	if err != nil {
		t.Fatalf("transient 502s should be retried, got: %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
	if len(findings) != 1 {
		t.Errorf("got %d findings, want 1", len(findings))
	}
}

// Retry, then fail -- never fall back to metadata-derived remediation. A fix
// built on guessed remediation is worse than no fix.
func TestKnoxIQ_ListByAnalysis_failsAfterExhaustingRetries(t *testing.T) {
	withFastRetries(t)
	client, mux, _, teardown := setup()
	defer teardown()

	var attempts int
	mux.HandleFunc("/api/knoxiq/analyses/11829/findings", func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	_, err := client.KnoxIQ.ListByAnalysis(context.Background(), 11829)
	if err == nil {
		t.Fatal("want an error once retries are exhausted")
	}
	if attempts != knoxiqMaxAttempts {
		t.Errorf("attempts = %d, want %d", attempts, knoxiqMaxAttempts)
	}
}

func TestKnoxIQ_ListByAnalysis_sendsTokenAuth(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	var gotAuth string
	mux.HandleFunc("/api/knoxiq/analyses/11829/findings", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, `{"count":0,"results":[]}`)
	})

	if _, err := client.KnoxIQ.ListByAnalysis(context.Background(), 11829); err != nil {
		t.Fatalf("ListByAnalysis returned error: %v", err)
	}
	if want := "Token token"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
}
