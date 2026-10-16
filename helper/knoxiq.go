package helper

import (
	"context"
	"fmt"

	"github.com/appknox/appknox-go/appknox"
)

// checkKnoxIQReady is the autofix gate: skip without a file id, else require COMPLETED.
func checkKnoxIQReady(ctx context.Context, fileID int) error {
	if fileID <= 0 {
		return nil
	}
	return requireKnoxIQCompleted(ctx, getClient(), fileID)
}

// requireKnoxIQCompleted fails autofix unless KnoxIQ has finished for the file.
// Skipped when fileID is unset (manual --finding has nothing to check).
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
	return fmt.Errorf(
		"knoxiq is not completed for file %d (sast=%s, dast=%s)",
		fileID,
		appknox.KnoxIQScanStatusLabel(st.SASTStatus),
		appknox.KnoxIQScanStatusLabel(st.DASTStatus),
	)
}
