package appknox

import (
	"testing"
	"time"
)

// The submission timeout decides whether a slow-but-healthy backend reads as a
// failure. It used to be a hardcoded 5 minutes; an mfva upload on 8 Sep took
// about 14 minutes to become a file, so the CLI reported "Request timed out" and
// exited non-zero on a run whose upload, file creation and static scan had all
// succeeded.
//
// The override matters most in the direction nobody thinks to test: a malformed
// value must not collapse to a zero timeout, which would fail every upload
// instantly and look exactly like the bug being fixed.
func TestSubmissionTimeoutFromEnv(t *testing.T) {
	const def = 30 * time.Minute

	cases := []struct {
		name string
		env  string
		want time.Duration
	}{
		{"unset falls back", "", def},
		{"positive integer wins", "45", 45 * time.Minute},
		{"one minute is honoured", "1", time.Minute},
		{"zero is refused", "0", def},
		{"negative is refused", "-5", def},
		{"non-numeric is refused", "soon", def},
		{"float is refused", "12.5", def},
		{"whitespace is refused", "  ", def},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("APPKNOX_SUBMISSION_TIMEOUT_MINUTES", tc.env)
			if got := submissionTimeoutFromEnv(def); got != tc.want {
				t.Fatalf("APPKNOX_SUBMISSION_TIMEOUT_MINUTES=%q: got %s, want %s",
					tc.env, got, tc.want)
			}
		})
	}
}

// The shipped default has to exceed what the backend actually takes, or the fix
// achieves nothing. 14 minutes was observed; 30 leaves real headroom.
func TestSubmissionTimeoutDefaultExceedsObservedBackendLatency(t *testing.T) {
	const observed = 14 * time.Minute
	if SubmissionTimeout <= observed {
		t.Fatalf("SubmissionTimeout is %s, which does not clear the %s already "+
			"observed against the live backend", SubmissionTimeout, observed)
	}
}
