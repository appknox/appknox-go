package appknox

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// withFastBackoff collapses the retry delay so tests do not sleep.
func withFastBackoff(t *testing.T) {
	t.Helper()
	prev := knoxiqRetryBaseDelay
	knoxiqRetryBaseDelay = time.Millisecond
	t.Cleanup(func() { knoxiqRetryBaseDelay = prev })
}

func TestGetWithRetry_RetriesServerErrorThenSucceeds(t *testing.T) {
	withFastBackoff(t)
	client, mux, _, teardown := setup()
	defer teardown()

	calls := 0
	mux.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, `{"count":0,"results":[]}`)
	})

	var out DRFResponseKnoxIQFinding
	if err := client.KnoxIQ.getWithRetry(context.Background(), "x", &out); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("want 3 attempts, got %d", calls)
	}
}

func TestGetWithRetry_DoesNotRetryUnauthorized(t *testing.T) {
	withFastBackoff(t)
	client, mux, _, teardown := setup()
	defer teardown()

	calls := 0
	mux.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
	})

	var out DRFResponseKnoxIQFinding
	err := client.KnoxIQ.getWithRetry(context.Background(), "x", &out)
	if err == nil {
		t.Fatal("401 must be returned, not swallowed")
	}
	if calls != 1 {
		t.Fatalf("a rejected credential must not be retried, got %d attempts", calls)
	}
}

func TestListByAnalysis_EmptyIsNotAnError(t *testing.T) {
	withFastBackoff(t)
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/analyses/1/findings", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"count":0,"results":[]}`)
	})

	got, err := client.KnoxIQ.ListByAnalysis(context.Background(), 1)
	if err != nil {
		t.Fatalf("KnoxIQ reached with nothing to report is not an error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 findings, got %d", len(got))
	}
}
