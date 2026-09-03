package cmd

import "testing"

// NOTE: reportsKnoxIQCmd.Run exits the process (real API calls, no mocking
// infrastructure here — same boundary as cicheck_test.go), so only the
// testable-in-isolation Args validation is covered here. The Run-level exit
// codes (file id parse failure, ProcessKnoxIQReport error) were verified
// manually against sherlock-knoxiq-uat: both now exit 1 instead of 0.
func TestReportsKnoxIQCommand_RequiredFileIDArg(t *testing.T) {
	if err := reportsKnoxIQCmd.Args(reportsKnoxIQCmd, []string{}); err == nil {
		t.Error("expected error when file id is not provided")
	}
	if err := reportsKnoxIQCmd.Args(reportsKnoxIQCmd, []string{"242"}); err != nil {
		t.Errorf("expected no error when file id is provided, got: %v", err)
	}
}
