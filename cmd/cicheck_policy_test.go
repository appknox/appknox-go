package cmd

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/appknox/appknox-go/helper"
)

// captureCmdStderr mirrors helper's own captureStderr test helper (unexported
// there, so not reusable across packages): it redirects os.Stderr for the
// duration of f and returns whatever was written, since helper.PrintError
// (used by the corrupt-state-file warning) writes to os.Stderr rather than
// returning anything a test can assert on directly.
func captureCmdStderr(f func()) string {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	f()

	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// writeCorruptPolicyFile overwrites path with invalid JSON, for testing the
// "corrupt state file falls back to the default" rule.
func writeCorruptPolicyFile(path string) error {
	return os.WriteFile(path, []byte("{not json"), 0o600)
}

// withPolicyConfigDir points policyConfigDir at a temp directory for the
// duration of the test, restoring the previous value on cleanup. This is the
// seam cicheck's and autofix's policy-state code go through instead of
// resolving $HOME/.config directly, so tests never touch the real config
// file.
func withPolicyConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := policyConfigDir
	policyConfigDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { policyConfigDir = prev })
	return dir
}

func TestRecordCiCheckPolicyState_WritesRiskThresholdName(t *testing.T) {
	resetCiCheckFlags()
	dir := withPolicyConfigDir(t)

	if err := cicheckCmd.Flags().Set(flagRiskThreshold, "critical"); err != nil {
		t.Fatal(err)
	}
	policy, err := parseCiPolicy(cicheckCmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	recordCiCheckPolicyState(cicheckCmd, 42, policy)

	name, found, err := helper.ReadCiCheckPolicy(dir, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || name != "critical" {
		t.Fatalf("want (\"critical\", true), got (%q, %v)", name, found)
	}

	resetCiCheckFlags()
}

func TestRecordCiCheckPolicyState_MergesAcrossFileIDs(t *testing.T) {
	resetCiCheckFlags()
	dir := withPolicyConfigDir(t)

	if err := cicheckCmd.Flags().Set(flagRiskThreshold, "low"); err != nil {
		t.Fatal(err)
	}
	policy1, err := parseCiPolicy(cicheckCmd)
	if err != nil {
		t.Fatal(err)
	}
	recordCiCheckPolicyState(cicheckCmd, 1, policy1)

	resetCiCheckFlags()
	if err := cicheckCmd.Flags().Set(flagRiskThreshold, "high"); err != nil {
		t.Fatal(err)
	}
	policy2, err := parseCiPolicy(cicheckCmd)
	if err != nil {
		t.Fatal(err)
	}
	recordCiCheckPolicyState(cicheckCmd, 2, policy2)

	name1, found1, err := helper.ReadCiCheckPolicy(dir, 1)
	if err != nil || !found1 || name1 != "low" {
		t.Fatalf("want file 1 = low, got (%q, %v, %v)", name1, found1, err)
	}
	name2, found2, err := helper.ReadCiCheckPolicy(dir, 2)
	if err != nil || !found2 || name2 != "high" {
		t.Fatalf("want file 2 = high, got (%q, %v, %v)", name2, found2, err)
	}

	resetCiCheckFlags()
}

func TestRecordCiCheckPolicyState_SkipsWhenRiskGateInactive(t *testing.T) {
	resetCiCheckFlags()
	dir := withPolicyConfigDir(t)

	if err := cicheckCmd.Flags().Set(flagHealthScoreThreshold, "80"); err != nil {
		t.Fatal(err)
	}
	policy, err := parseCiPolicy(cicheckCmd)
	if err != nil {
		t.Fatal(err)
	}
	recordCiCheckPolicyState(cicheckCmd, 5, policy)

	_, found, err := helper.ReadCiCheckPolicy(dir, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("want nothing recorded when the risk gate is inactive (health-score mode)")
	}

	resetCiCheckFlags()
}

// TestAutofixRiskThreshold_FlagWins covers priority (a): an explicit
// --risk-threshold flag beats everything else, even when the env var and a
// recorded cicheck policy also apply.
func TestAutofixRiskThreshold_FlagWins(t *testing.T) {
	resetAutofixFlags()
	dir := withPolicyConfigDir(t)
	t.Setenv("APPKNOX_RISK_THRESHOLD", "high")
	if err := helper.RecordCiCheckPolicy(dir, 77, "low"); err != nil {
		t.Fatal(err)
	}
	if err := autofixCmd.Flags().Set(flagRiskThreshold, "critical"); err != nil {
		t.Fatal(err)
	}

	level, name, source, err := autofixRiskThreshold(autofixCmd, 77)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if level != 4 || name != "critical" || source != riskThresholdSourceFlag {
		t.Fatalf("want (4, critical, %q), got (%d, %q, %q)", riskThresholdSourceFlag, level, name, source)
	}

	resetAutofixFlags()
}

// TestAutofixRiskThreshold_EnvBeatsRecordedPolicy covers priority (b): with
// no explicit flag, APPKNOX_RISK_THRESHOLD wins over whatever cicheck
// recorded.
func TestAutofixRiskThreshold_EnvBeatsRecordedPolicy(t *testing.T) {
	resetAutofixFlags()
	dir := withPolicyConfigDir(t)
	t.Setenv("APPKNOX_RISK_THRESHOLD", "medium")
	if err := helper.RecordCiCheckPolicy(dir, 77, "critical"); err != nil {
		t.Fatal(err)
	}

	level, name, source, err := autofixRiskThreshold(autofixCmd, 77)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if level != 2 || name != "medium" || source != riskThresholdSourceEnv {
		t.Fatalf("want (2, medium, %q), got (%d, %q, %q)", riskThresholdSourceEnv, level, name, source)
	}

	resetAutofixFlags()
}

// TestAutofixRiskThreshold_PicksUpRecordedPolicyForSameFileID covers
// priority (c): no flag, no env, the value cicheck recorded for THIS file id
// wins, and a value recorded for a different file id is ignored.
func TestAutofixRiskThreshold_PicksUpRecordedPolicyForSameFileID(t *testing.T) {
	resetAutofixFlags()
	dir := withPolicyConfigDir(t)
	if err := helper.RecordCiCheckPolicy(dir, 77, "critical"); err != nil {
		t.Fatal(err)
	}
	if err := helper.RecordCiCheckPolicy(dir, 78, "high"); err != nil {
		t.Fatal(err)
	}

	level, name, source, err := autofixRiskThreshold(autofixCmd, 77)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if level != 4 || name != "critical" {
		t.Fatalf("want (4, critical), got (%d, %q)", level, name)
	}
	if source != "from cicheck on file 77" {
		t.Fatalf("want source 'from cicheck on file 77', got %q", source)
	}

	// A different file id must not pick up file 77's recorded value.
	level2, name2, source2, err := autofixRiskThreshold(autofixCmd, 999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if level2 != 1 || name2 != "low" || source2 != riskThresholdSourceDefault {
		t.Fatalf("want the default for an unrecorded file id, got (%d, %q, %q)", level2, name2, source2)
	}

	resetAutofixFlags()
}

// TestAutofixRiskThreshold_DefaultsToLow covers priority (d): nothing set
// anywhere falls back to "low".
func TestAutofixRiskThreshold_DefaultsToLow(t *testing.T) {
	resetAutofixFlags()
	withPolicyConfigDir(t)

	level, name, source, err := autofixRiskThreshold(autofixCmd, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if level != 1 || name != "low" || source != riskThresholdSourceDefault {
		t.Fatalf("want (1, low, %q), got (%d, %q, %q)", riskThresholdSourceDefault, level, name, source)
	}
}

// TestAutofixRiskThreshold_MissingStateFileFallsBackToDefault: no recorded
// policy file at all must not error, just fall back.
func TestAutofixRiskThreshold_MissingStateFileFallsBackToDefault(t *testing.T) {
	resetAutofixFlags()
	withPolicyConfigDir(t) // empty directory, no cicheck-policy.json written

	level, name, source, err := autofixRiskThreshold(autofixCmd, 77)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if level != 1 || name != "low" || source != riskThresholdSourceDefault {
		t.Fatalf("want the default, got (%d, %q, %q)", level, name, source)
	}
}

// TestAutofixRiskThreshold_CorruptStateFileFallsBackToDefault: a corrupt
// cicheck-policy.json must not fail the run, only warn and fall back.
func TestAutofixRiskThreshold_CorruptStateFileFallsBackToDefault(t *testing.T) {
	resetAutofixFlags()
	dir := withPolicyConfigDir(t)
	if err := helper.RecordCiCheckPolicy(dir, 1, "low"); err != nil {
		t.Fatal(err)
	}
	// Corrupt the state file cicheck-policy.json after it exists.
	corrupt := dir + "/cicheck-policy.json"
	if err := writeCorruptPolicyFile(corrupt); err != nil {
		t.Fatal(err)
	}

	printed := captureCmdStderr(func() {
		level, name, source, err := autofixRiskThreshold(autofixCmd, 1)
		if err != nil {
			t.Fatalf("a corrupt state file must not fail autofix, got: %v", err)
		}
		if level != 1 || name != "low" || source != riskThresholdSourceDefault {
			t.Fatalf("want the default on a corrupt state file, got (%d, %q, %q)", level, name, source)
		}
	})
	if printed == "" {
		t.Fatal("want a warning printed for a corrupt state file")
	}
}

// TestAutofixRiskThreshold_InvalidEnvValueErrors covers the "invalid env
// value is an error" rule.
func TestAutofixRiskThreshold_InvalidEnvValueErrors(t *testing.T) {
	resetAutofixFlags()
	withPolicyConfigDir(t)
	t.Setenv("APPKNOX_RISK_THRESHOLD", "extreme")

	if _, _, _, err := autofixRiskThreshold(autofixCmd, 0); err == nil {
		t.Fatal("want an error for an invalid APPKNOX_RISK_THRESHOLD value")
	}
}
