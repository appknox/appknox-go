package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// autofixRiskThresholdEnv is the env var an operator can set to apply a
// severity policy to `autofix` without a --risk-threshold flag on every
// invocation, mirroring how other appknox-go flags (e.g. --host,
// --access-token) have an APPKNOX_ env fallback.
const autofixRiskThresholdEnv = "APPKNOX_RISK_THRESHOLD"

// Source labels for autofixRiskThreshold's "Risk threshold: <name> (<source>)"
// summary line. riskThresholdSourceEnv doubles as the env var's own name.
const (
	riskThresholdSourceFlag    = "flag"
	riskThresholdSourceEnv     = autofixRiskThresholdEnv
	riskThresholdSourceDefault = "default"
)

// policyConfigDir resolves the directory holding cicheck's policy state file
// (cicheck-policy.json) -- the same directory as the default appknox.json
// config. A package-level var, not a plain function, so tests can point it
// at a temp directory (see withPolicyConfigDir in cicheck_policy_test.go)
// instead of overriding $HOME/$USERPROFILE.
var policyConfigDir = func() (string, error) {
	configFile, err := defaultConfigFile()
	if err != nil {
		return "", err
	}
	return filepath.Dir(configFile), nil
}

// recordCiCheckPolicyState persists this cicheck run's --risk-threshold name
// so a later `autofix --file-id <fileID>` run on the same file can inherit
// it without the operator passing --risk-threshold twice (see
// autofixRiskThreshold below and helper.RecordCiCheckPolicy). Only written
// when the risk gate is actually active -- health-score mode has no risk
// threshold to record.
//
// A write failure is a warning, never fatal to cicheck: this state is a
// convenience for a later autofix run, not a cicheck responsibility.
func recordCiCheckPolicyState(cmd *cobra.Command, fileID int, policy helper.CiPolicy) {
	if policy.RiskThreshold < 1 {
		return
	}
	thresholdName, _ := cmd.Flags().GetString(flagRiskThreshold)
	dir, err := policyConfigDir()
	if err != nil {
		helper.PrintError(fmt.Errorf("cicheck-policy: resolve config dir: %w", err))
		return
	}
	if err := helper.RecordCiCheckPolicy(dir, fileID, strings.ToLower(thresholdName)); err != nil {
		helper.PrintError(fmt.Errorf("cicheck-policy: %w", err))
	}
}

// autofixRiskThreshold resolves autofix's severity policy, first match wins:
//
//  1. an explicit --risk-threshold flag (cmd.Flags().Changed)
//  2. the APPKNOX_RISK_THRESHOLD env var, if set and valid
//  3. whatever cicheck recorded for this --file-id in cicheck-policy.json
//  4. "low" -- today's default, unchanged from before this policy existed
//
// It returns the resolved level (1-4), the canonical threshold name, and a
// human-readable source label for the "Risk threshold: <name> (<source>)"
// line cmd/autofix.go prints. An invalid value at step 1 or 2 is an error,
// the same way cicheck itself rejects an invalid --risk-threshold. A
// resolution problem at step 3 (missing or corrupt state, or an
// unresolvable config dir) never errors the run: see
// recordedRiskThresholdName.
func autofixRiskThreshold(cmd *cobra.Command, fileID int) (level int, name string, source string, err error) {
	if cmd.Flags().Changed(flagRiskThreshold) {
		value, _ := cmd.Flags().GetString(flagRiskThreshold)
		level, err = riskThresholdFromName(value)
		if err != nil {
			return 0, "", "", err
		}
		return level, strings.ToLower(value), riskThresholdSourceFlag, nil
	}

	if envValue, ok := os.LookupEnv(autofixRiskThresholdEnv); ok && envValue != "" {
		level, err = riskThresholdFromName(envValue)
		if err != nil {
			return 0, "", "", fmt.Errorf("%s: %w", autofixRiskThresholdEnv, err)
		}
		return level, strings.ToLower(envValue), riskThresholdSourceEnv, nil
	}

	if recorded, recordedSource, ok := recordedRiskThresholdName(fileID); ok {
		level, err = riskThresholdFromName(recorded)
		if err != nil {
			return 0, "", "", fmt.Errorf("recorded cicheck policy for file %d: %w", fileID, err)
		}
		return level, strings.ToLower(recorded), recordedSource, nil
	}

	return 1, "low", riskThresholdSourceDefault, nil
}

// recordedRiskThresholdName reads cicheck's recorded threshold for fileID.
// Anything short of an actual recorded value -- no fileID, no config dir, no
// state file, no entry for this fileID, or a CORRUPT state file -- resolves
// as "not found" so autofixRiskThreshold falls through to its default,
// exactly like a fresh checkout that has never run cicheck. A corrupt state
// file additionally prints a warning, since that is a real (if non-fatal)
// problem worth surfacing, unlike a simply-absent one.
func recordedRiskThresholdName(fileID int) (name string, source string, ok bool) {
	if fileID <= 0 {
		return "", "", false
	}
	dir, err := policyConfigDir()
	if err != nil {
		return "", "", false
	}
	recorded, found, err := helper.ReadCiCheckPolicy(dir, fileID)
	if err != nil {
		helper.PrintError(fmt.Errorf("cicheck-policy: %w (falling back to default)", err))
		return "", "", false
	}
	if !found {
		return "", "", false
	}
	return recorded, fmt.Sprintf("from cicheck on file %d", fileID), true
}
