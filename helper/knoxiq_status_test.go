package helper

import (
	"context"
	"errors"
	"testing"

	"github.com/appknox/appknox-go/appknox"
	"github.com/stretchr/testify/require"
)

// Manual --finding mode never consults KnoxIQ, so there is no scan whose
// readiness could be in question.
func TestRequireKnoxIQCompleted_SkippedWithoutFileID(t *testing.T) {
	require.NoError(t, requireKnoxIQCompleted(context.Background(), nil, 0))
}

// A missing client must not read as permission to proceed.
func TestRequireKnoxIQCompleted_FailsWithoutAClient(t *testing.T) {
	require.Error(t, requireKnoxIQCompleted(context.Background(), nil, 7))
}

func TestKnoxIQFileScanStatus_Completed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sast, dast int
		want       bool
	}{
		{"sast completed", appknox.KnoxIQScanStatusCompleted, appknox.KnoxIQScanStatusNotTriggered, true},
		{"dast-only file", appknox.KnoxIQScanStatusDisabled, appknox.KnoxIQScanStatusCompleted, true},
		{"still running", appknox.KnoxIQScanStatusRunning, appknox.KnoxIQScanStatusRunning, false},
		{"never triggered", appknox.KnoxIQScanStatusNotTriggered, appknox.KnoxIQScanStatusNotTriggered, false},
		{"errored", appknox.KnoxIQScanStatusErrored, appknox.KnoxIQScanStatusDisabled, false},
		{"disabled with no dast", appknox.KnoxIQScanStatusDisabled, appknox.KnoxIQScanStatusDisabled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &appknox.KnoxIQFileScanStatus{SASTStatus: tc.sast, DASTStatus: tc.dast}
			require.Equal(t, tc.want, st.Completed())
		})
	}
}

// A nil status is not complete. The client failing to populate it must never
// be mistaken for a finished scan.
func TestKnoxIQFileScanStatus_NilIsNotCompleted(t *testing.T) {
	var st *appknox.KnoxIQFileScanStatus
	require.False(t, st.Completed())
}

// An unfamiliar status must surface its number rather than be rendered as a
// known label -- that value is exactly what an operator needs to see.
func TestKnoxIQScanStatusLabel_NamesUnknownValues(t *testing.T) {
	require.Equal(t, "Completed", appknox.KnoxIQScanStatusLabel(appknox.KnoxIQScanStatusCompleted))
	require.Equal(t, "Unknown(99)", appknox.KnoxIQScanStatusLabel(99))
}

// The gate must stop the run BEFORE anything is fetched or any model turn is
// paid for. If it did not, an unfinished scan would look like a clean file.
func TestRunAutofix_StopsWhenKnoxIQIsNotReady(t *testing.T) {
	d := deps("app/A.java", fixResult{}, oneClass("x", "y"))
	fetched := false
	d.fetch = func(context.Context, int, int) (FindingInputs, error) {
		fetched = true
		return FindingInputs{}, nil
	}
	d.knoxiqReady = func(context.Context, int) error { return errors.New("knoxiq is not completed") }

	_, err := runAutofix(context.Background(), appknoxOpts(t.TempDir()), d)

	require.Error(t, err)
	require.False(t, fetched, "must not fetch findings before KnoxIQ is ready")
}
