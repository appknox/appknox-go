package helper

import (
	"context"
	"fmt"

	"github.com/appknox/appknox-go/appknox"
)

// The readiness gate, ported from feat/autofix-cli (dc3453f).
//
// Autofix takes its remediation, its verification criteria and its class hints
// from KnoxIQ. Running before KnoxIQ has finished does not fail: the API
// returns an empty finding set, which reads downstream as "nothing fixable" and
// the run exits 0 reporting a clean file. That is the worst available outcome
// -- a green pipeline over a scan that had not started.
//
// So the gate runs FIRST, before targets are resolved and before any model turn
// is paid for, and it fails loudly with the actual SAST/DAST status.

// checkKnoxIQReady is the autofix gate: skip without a file id, else require
// that KnoxIQ has completed.
//
// Skipped for fileID <= 0 because manual --finding mode never consults KnoxIQ;
// there is no scan whose readiness could be in question.
func checkKnoxIQReady(ctx context.Context, fileID int) error {
	if fileID <= 0 {
		return nil
	}
	return requireKnoxIQCompleted(ctx, getClient(), fileID)
}

// requireKnoxIQCompleted fails unless KnoxIQ has finished for the file.
//
// Takes the client as a parameter so the gate is testable without a network;
// checkKnoxIQReady supplies the real one.
func requireKnoxIQCompleted(ctx context.Context, client *appknox.Client, fileID int) error {
	if fileID <= 0 {
		return nil
	}
	if client == nil {
		return fmt.Errorf("knoxiq status check failed: missing Appknox client")
	}
	st, _, err := client.KnoxIQ.GetScanStatus(ctx, fileID)
	if err != nil {
		return fmt.Errorf("knoxiq status check failed: %w", err)
	}
	if st.Completed() {
		return nil
	}
	// Name both statuses. "Not ready" sends the operator looking at the wrong
	// thing; "sast=Running" says wait, while "sast=Not Triggered" says the
	// upload never asked for KnoxIQ at all -- two different problems with two
	// different fixes.
	return fmt.Errorf(
		"knoxiq is not completed for file %d (sast=%s, dast=%s)",
		fileID,
		appknox.KnoxIQScanStatusLabel(st.SASTStatus),
		appknox.KnoxIQScanStatusLabel(st.DASTStatus),
	)
}
