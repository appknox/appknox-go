package helper

import (
	"context"
	"errors"
	"fmt"

	"github.com/appknox/appknox-go/appknox"
)

// errKnoxIQPending marks a KnoxIQ scan that is still running: worth waiting for.
var errKnoxIQPending = errors.New("knoxiq is still running")

// checkKnoxIQReady is the autofix gate: wait until KnoxIQ has finished for the
// file. A pipeline usually runs autofix right after the scan, so a scan still
// in progress is waited out rather than failed (until the run's deadline).
func checkKnoxIQReady(ctx context.Context, fileID int) error {
	return awaitKnoxIQCompleted(ctx, getClient(), fileID)
}

func awaitKnoxIQCompleted(ctx context.Context, client *appknox.Client, fileID int) error {
	announced := false
	for {
		err := requireKnoxIQCompleted(ctx, client, fileID)
		if !errors.Is(err, errKnoxIQPending) {
			return err
		}
		if !announced {
			fmt.Printf("Waiting for KnoxIQ to finish on file %d...\n", fileID)
			announced = true
		}
		if ctx.Err() != nil {
			return fmt.Errorf("knoxiq did not finish for file %d before the autofix deadline: %w", fileID, err)
		}
		autofixSleep(autofixPollInterval * 5)
	}
}

// requireKnoxIQCompleted checks KnoxIQ once. It returns errKnoxIQPending
// (wrapped) while the scan is pending or running, and a plain error when it
// will never complete on its own: errored, disabled or never triggered.
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
	err = fmt.Errorf(
		"knoxiq is not completed for file %d (sast=%s, dast=%s)",
		fileID,
		appknox.KnoxIQScanStatusLabel(st.SASTStatus),
		appknox.KnoxIQScanStatusLabel(st.DASTStatus),
	)
	if inProgress(st.SASTStatus) || inProgress(st.DASTStatus) {
		return fmt.Errorf("%w: %v", errKnoxIQPending, err)
	}
	return err
}

func inProgress(status int) bool {
	return status == appknox.KnoxIQScanStatusPending || status == appknox.KnoxIQScanStatusRunning
}
