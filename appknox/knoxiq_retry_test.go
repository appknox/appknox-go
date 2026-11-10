package appknox

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
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

// captureStdout runs fn and returns whatever it wrote to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	prev := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = prev
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// M4: ListByAnalysis reads exactly one page (knoxiqPageLimit) and does NOT
// paginate. When the server reports more findings than that page returned,
// silently keeping only the first page would let a fix run believe it saw
// every finding when it did not -- this must print a one-line warning
// instead.
func TestListByAnalysis_WarnsWhenTruncatedByPageLimit(t *testing.T) {
	withFastBackoff(t)
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/analyses/1/findings", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"count":150,"results":[{"finding_id":"a"}]}`)
	})

	var got []*KnoxIQFinding
	var err error
	output := captureStdout(t, func() {
		got, err = client.KnoxIQ.ListByAnalysis(context.Background(), 1)
	})
	if err != nil {
		t.Fatalf("a truncated page is not an error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want the one finding on the fetched page, got %d", len(got))
	}
	if output == "" {
		t.Fatal("want a printed warning when count (150) exceeds the findings fetched (1)")
	}
}

// The converse of the above: a page that already holds every finding must
// print nothing.
func TestListByAnalysis_NoWarningWhenNotTruncated(t *testing.T) {
	withFastBackoff(t)
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/api/knoxiq/analyses/1/findings", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"count":1,"results":[{"finding_id":"a"}]}`)
	})

	output := captureStdout(t, func() {
		if _, err := client.KnoxIQ.ListByAnalysis(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
	})
	if output != "" {
		t.Fatalf("want no warning when the page already holds every finding, got %q", output)
	}
}
