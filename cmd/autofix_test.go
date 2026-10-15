package cmd

import (
	"testing"

	"github.com/spf13/pflag"
)

// resetAutofixFlags resets all autofixCmd flags to their default state,
// mirroring resetCiCheckFlags in cicheck_test.go.
func resetAutofixFlags() {
	autofixCmd.Flags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
		f.Value.Set(f.DefValue)
	})
}

// TestAutofixCommand_RiskThresholdFlagDefaultsToLow is the RED test for the
// flag itself: autofix must register the same --risk-threshold flag cicheck
// uses, defaulting to "low" so an unset flag keeps today's autofix behaviour
// (RiskThreshold 1 via the runAutofix <=0 guard).
func TestAutofixCommand_RiskThresholdFlagDefaultsToLow(t *testing.T) {
	resetAutofixFlags()

	flag := autofixCmd.Flags().Lookup(flagRiskThreshold)
	if flag == nil {
		t.Fatal("expected autofix to register the risk-threshold flag")
	}
	if flag.DefValue != "low" {
		t.Errorf("want default risk-threshold 'low', got %q", flag.DefValue)
	}
	if flag.Shorthand != "r" {
		t.Errorf("want shorthand -r, got %q", flag.Shorthand)
	}

	resetAutofixFlags()
}

// TestAutofixCommand_RiskThresholdCriticalMapsToFour confirms autofix
// reuses cicheck's own parseRiskThreshold instead of a second mapping.
func TestAutofixCommand_RiskThresholdCriticalMapsToFour(t *testing.T) {
	resetAutofixFlags()

	if err := autofixCmd.Flags().Set(flagRiskThreshold, "critical"); err != nil {
		t.Fatalf("unexpected error setting flag: %v", err)
	}
	got, err := parseRiskThreshold(autofixCmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 4 {
		t.Errorf("want risk threshold 4 for 'critical', got %d", got)
	}

	resetAutofixFlags()
}

// TestAutofixCommand_RiskThresholdInvalidValueErrors confirms an invalid
// value is rejected the same way cicheck rejects it.
func TestAutofixCommand_RiskThresholdInvalidValueErrors(t *testing.T) {
	resetAutofixFlags()

	if err := autofixCmd.Flags().Set(flagRiskThreshold, "extreme"); err != nil {
		t.Fatalf("unexpected error setting flag: %v", err)
	}
	if _, err := parseRiskThreshold(autofixCmd); err == nil {
		t.Fatal("want an error for an invalid risk threshold value")
	}

	resetAutofixFlags()
}

// TestAutofixCommand_RiskThresholdShorthandNoCollision guards R1 of the
// brief: -r on autofix must not collide with any other autofix flag or any
// persistent flag inherited from the root command.
func TestAutofixCommand_RiskThresholdShorthandNoCollision(t *testing.T) {
	seen := map[string]string{}
	visit := func(f *pflag.Flag) {
		if f.Shorthand == "" {
			return
		}
		if other, ok := seen[f.Shorthand]; ok && other != f.Name {
			t.Errorf("shorthand -%s used by both %q and %q", f.Shorthand, other, f.Name)
		}
		seen[f.Shorthand] = f.Name
	}
	autofixCmd.Flags().VisitAll(visit)
	RootCmd.PersistentFlags().VisitAll(visit)
}
