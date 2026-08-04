package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func resetSarifFlags() {
	sarifCmd.Flags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
		f.Value.Set(f.DefValue)
	})
}

func TestSarifCommand_RequiredFileIDArg(t *testing.T) {
	if err := sarifCmd.Args(sarifCmd, []string{}); err == nil {
		t.Error("expected error when file id is not provided")
	} else if !strings.Contains(err.Error(), "file id is required") {
		t.Errorf("expected error about file id, got: %v", err)
	}

	if err := sarifCmd.Args(sarifCmd, []string{"12345"}); err != nil {
		t.Errorf("expected no error when file id is provided, got: %v", err)
	}
}

func TestSarifCommand_RiskThresholdDefault(t *testing.T) {
	resetSarifFlags()
	defer resetSarifFlags()

	val, _ := sarifCmd.Flags().GetString("risk-threshold")
	if val != "low" {
		t.Errorf("expected default risk-threshold 'low', got %q", val)
	}
}

// TestSarifCommand_RiskThresholdSharedParser confirms sarif reuses cicheck's
// parseRiskThreshold (and so gains "critical" support for free) instead of
// duplicating its own switch/case.
func TestSarifCommand_RiskThresholdSharedParser(t *testing.T) {
	resetSarifFlags()
	defer resetSarifFlags()

	sarifCmd.Flags().Set("risk-threshold", "critical")
	got, err := parseRiskThreshold(sarifCmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 4 {
		t.Errorf("expected 4 for critical, got %d", got)
	}
}

func TestKnoxIQTimeoutMinutes_Range(t *testing.T) {
	defer viper.Set("knoxiq-timeout", 30)

	viper.Set("knoxiq-timeout", 300)
	if _, err := knoxIQTimeoutMinutes(); err == nil {
		t.Error("expected error for out-of-range knoxiq-timeout")
	}

	viper.Set("knoxiq-timeout", 30)
	got, err := knoxIQTimeoutMinutes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 30 {
		t.Errorf("expected 30, got %d", got)
	}
}
