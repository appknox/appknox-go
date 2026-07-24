package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// NOTE: These tests validate flag parsing and validation logic.
// They do not execute cicheckCmd.Run() as that requires real API calls
// and would need mocking infrastructure. The Run() validation logic
// (mutual exclusivity, range checks) is tested indirectly through flag state.

func executeCommand(root *cobra.Command, args ...string) (output string, err error) {
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)

	err = root.Execute()
	return buf.String(), err
}

func TestCiCheckCommand_BothThresholdsProvided(t *testing.T) {
	// Reset command for each test
	cicheckCmd.Flags().Set("risk-threshold", "low")
	cicheckCmd.Flags().Set("health-score-threshold", "80")

	// We expect this to fail since both flags are provided
	// The command will attempt to run, but we can't test execution without a real API
	// So we verify that the flags can be set, but the logic check happens in Run

	riskChanged := cicheckCmd.Flags().Changed("risk-threshold")
	healthChanged := cicheckCmd.Flags().Changed("health-score-threshold")

	if !riskChanged {
		t.Error("Expected risk-threshold flag to be marked as changed")
	}
	if !healthChanged {
		t.Error("Expected health-score-threshold flag to be marked as changed")
	}

	// Both are changed, which should trigger error in Run function
	if !(riskChanged && healthChanged) {
		t.Error("Both flags should be changed to test mutual exclusivity")
	}

	// Reset flags for next test
	resetCiCheckFlags()
}

func TestCiCheckCommand_OnlyRiskThreshold(t *testing.T) {
	resetCiCheckFlags()

	cicheckCmd.Flags().Set("risk-threshold", "high")

	riskChanged := cicheckCmd.Flags().Changed("risk-threshold")
	healthChanged := cicheckCmd.Flags().Changed("health-score-threshold")

	if !riskChanged {
		t.Error("Expected risk-threshold flag to be marked as changed")
	}
	if healthChanged {
		t.Error("Expected health-score-threshold flag to NOT be changed")
	}

	resetCiCheckFlags()
}

func TestCiCheckCommand_OnlyHealthScoreThreshold(t *testing.T) {
	resetCiCheckFlags()

	cicheckCmd.Flags().Set("health-score-threshold", "75")

	riskChanged := cicheckCmd.Flags().Changed("risk-threshold")
	healthChanged := cicheckCmd.Flags().Changed("health-score-threshold")

	if riskChanged {
		t.Error("Expected risk-threshold flag to NOT be changed")
	}
	if !healthChanged {
		t.Error("Expected health-score-threshold flag to be marked as changed")
	}

	resetCiCheckFlags()
}

func TestCiCheckCommand_NoThresholdsProvided(t *testing.T) {
	resetCiCheckFlags()

	riskChanged := cicheckCmd.Flags().Changed("risk-threshold")
	healthChanged := cicheckCmd.Flags().Changed("health-score-threshold")

	if riskChanged {
		t.Error("Expected risk-threshold flag to NOT be changed (should use default)")
	}
	if healthChanged {
		t.Error("Expected health-score-threshold flag to NOT be changed")
	}

	// Verify default value for risk-threshold
	riskVal, _ := cicheckCmd.Flags().GetString("risk-threshold")
	if riskVal != "low" {
		t.Errorf("Expected default risk-threshold to be 'low', got '%s'", riskVal)
	}

	resetCiCheckFlags()
}

func TestCiCheckCommand_HealthScoreValidation(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		shouldParse bool
	}{
		{"Valid 0", "0", true},
		{"Valid 50", "50", true},
		{"Valid 100", "100", true},
		{"Invalid negative", "-1", true}, // Parse succeeds, validation happens in Run
		{"Invalid > 100", "101", true},   // Parse succeeds, validation happens in Run
		{"Invalid string", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCiCheckFlags()
			err := cicheckCmd.Flags().Set("health-score-threshold", tt.value)

			if tt.shouldParse && err != nil {
				t.Errorf("Expected to parse value '%s', but got error: %v", tt.value, err)
			}
			if !tt.shouldParse && err == nil {
				t.Errorf("Expected parse error for value '%s', but got none", tt.value)
			}
		})
	}

	resetCiCheckFlags()
}

func TestCiCheckCommand_RiskThresholdValues(t *testing.T) {
	validValues := []string{"low", "medium", "high", "critical"}

	for _, val := range validValues {
		t.Run("Valid_"+val, func(t *testing.T) {
			resetCiCheckFlags()
			err := cicheckCmd.Flags().Set("risk-threshold", val)
			if err != nil {
				t.Errorf("Expected to set risk-threshold to '%s', got error: %v", val, err)
			}

			result, _ := cicheckCmd.Flags().GetString("risk-threshold")
			if result != val {
				t.Errorf("Expected risk-threshold to be '%s', got '%s'", val, result)
			}
		})
	}

	resetCiCheckFlags()
}

func TestCiCheckCommand_TimeoutFlag(t *testing.T) {
	resetCiCheckFlags()

	err := cicheckCmd.Flags().Set("timeout", "60")
	if err != nil {
		t.Errorf("Expected to set timeout, got error: %v", err)
	}

	val, _ := cicheckCmd.Flags().GetInt("timeout")
	if val != 60 {
		t.Errorf("Expected timeout to be 60, got %d", val)
	}

	// Test default value
	resetCiCheckFlags()
	defaultVal, _ := cicheckCmd.Flags().GetInt("timeout")
	if defaultVal != 30 {
		t.Errorf("Expected default timeout to be 30, got %d", defaultVal)
	}

	resetCiCheckFlags()
}

func TestCiCheckCommand_RequiredFileIDArg(t *testing.T) {
	// Test that file ID is required
	err := cicheckCmd.Args(cicheckCmd, []string{})
	if err == nil {
		t.Error("Expected error when file ID is not provided")
	}
	if err != nil && !strings.Contains(err.Error(), "file id is required") {
		t.Errorf("Expected error message about file id, got: %v", err)
	}

	// Test that file ID is accepted
	err = cicheckCmd.Args(cicheckCmd, []string{"12345"})
	if err != nil {
		t.Errorf("Expected no error when file ID is provided, got: %v", err)
	}
}

func TestParseCiPolicy_GateActivation(t *testing.T) {
	tests := []struct {
		name       string
		flags      map[string]string
		wantRisk   int
		wantLikeli int
		wantHealth int
		wantErr    bool
	}{
		{"default risk", map[string]string{}, 1, -1, -1, false},
		{"risk explicit", map[string]string{"risk-threshold": "high"}, 3, -1, -1, false},
		{"likelihood only disables risk", map[string]string{"exploit-likelihood-threshold": "high"}, -1, 4, -1, false},
		{"risk + likelihood", map[string]string{"risk-threshold": "medium", "exploit-likelihood-threshold": "low"}, 2, 2, -1, false},
		{"health + likelihood", map[string]string{"health-score-threshold": "80", "exploit-likelihood-threshold": "high"}, -1, 4, 80, false},
		{"risk + health error", map[string]string{"risk-threshold": "low", "health-score-threshold": "80"}, 0, 0, 0, true},
		{"invalid likelihood", map[string]string{"exploit-likelihood-threshold": "bad"}, 0, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCiCheckFlags()
			for k, v := range tt.flags {
				cicheckCmd.Flags().Set(k, v)
			}
			policy, err := parseCiPolicy(cicheckCmd)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if policy.RiskThreshold != tt.wantRisk {
				t.Errorf("risk = %d, want %d", policy.RiskThreshold, tt.wantRisk)
			}
			if policy.LikelihoodThreshold != tt.wantLikeli {
				t.Errorf("likelihood = %d, want %d", policy.LikelihoodThreshold, tt.wantLikeli)
			}
			if policy.HealthScoreThreshold != tt.wantHealth {
				t.Errorf("health = %d, want %d", policy.HealthScoreThreshold, tt.wantHealth)
			}
		})
	}
	resetCiCheckFlags()
}

func TestParseCiPolicy_KnoxIQTimeoutRange(t *testing.T) {
	resetCiCheckFlags()
	viper.Set("knoxiq-timeout", 300) // out of range
	if _, err := parseCiPolicy(cicheckCmd); err == nil {
		t.Error("expected error for out-of-range knoxiq-timeout")
	}
	viper.Set("knoxiq-timeout", 30) // restore default
	resetCiCheckFlags()
}

// resetCiCheckFlags resets all flags to their default state
func resetCiCheckFlags() {
	// Visit all flags and reset them
	cicheckCmd.Flags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
		f.Value.Set(f.DefValue)
	})
}
