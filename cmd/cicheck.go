package cmd

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// cicheckCmd represents the cicheck command
var cicheckCmd = &cobra.Command{
	Use:   "cicheck",
	Short: "Check for vulnerabilities based on risk or health score threshold.",
	Long:  `List all the vulnerabilities with the risk threshold greater or equal than the provided and fail the command, or pass the command when the file health score is greater than or equal to the provided health score threshold.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("file id is required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		fileID, err := strconv.Atoi(args[0])
		if err != nil {
			helper.PrintError(errors.New("Valid file id is required"))
			os.Exit(1)
		}
		policy, err := parseCiPolicy(cmd)
		if err != nil {
			helper.PrintError(err)
			os.Exit(1)
		}
		if policy.HealthScoreThreshold >= 0 {
			helper.ProcessHealthScoreCiCheck(fileID, policy)
			return
		}
		helper.ProcessCiCheck(fileID, policy)
	},
}

// parseCiPolicy resolves the active build-failure gates and timeouts from the
// cicheck flags. A threshold of -1 marks a gate inactive.
func parseCiPolicy(cmd *cobra.Command) (helper.CiPolicy, error) {
	policy := helper.CiPolicy{RiskThreshold: -1, LikelihoodThreshold: -1, HealthScoreThreshold: -1}

	staticMinutes, _ := cmd.Flags().GetInt("timeout")
	policy.StaticScanTimeout = time.Duration(staticMinutes) * time.Minute

	knoxiqMinutes := viper.GetInt("knoxiq-timeout")
	if knoxiqMinutes < 1 || knoxiqMinutes > 240 {
		return policy, errors.New("knoxiq-timeout must be between 1 and 240 minutes")
	}
	policy.KnoxIQTimeout = time.Duration(knoxiqMinutes) * time.Minute

	healthChanged := cmd.Flags().Changed("health-score-threshold")
	riskChanged := cmd.Flags().Changed("risk-threshold")
	likelihoodChanged := cmd.Flags().Changed("exploit-likelihood-threshold")

	if healthChanged && riskChanged {
		return policy, errors.New("only one of risk-threshold or health-score-threshold can be provided")
	}

	if err := applyHealthGate(cmd, &policy, healthChanged); err != nil {
		return policy, err
	}
	if err := applyLikelihoodGate(cmd, &policy, likelihoodChanged); err != nil {
		return policy, err
	}
	// The risk gate is active unless health mode is selected or the user gates
	// on likelihood alone (likelihood set without an explicit risk threshold).
	if !healthChanged && !(likelihoodChanged && !riskChanged) {
		risk, err := parseRiskThreshold(cmd)
		if err != nil {
			return policy, err
		}
		policy.RiskThreshold = risk
	}
	return policy, nil
}

func applyHealthGate(cmd *cobra.Command, policy *helper.CiPolicy, changed bool) error {
	if !changed {
		return nil
	}
	value, _ := cmd.Flags().GetInt("health-score-threshold")
	if value < 0 || value > 100 {
		return errors.New("health-score-threshold must be between 0 and 100")
	}
	policy.HealthScoreThreshold = value
	return nil
}

func applyLikelihoodGate(cmd *cobra.Command, policy *helper.CiPolicy, changed bool) error {
	if !changed {
		return nil
	}
	value, _ := cmd.Flags().GetString("exploit-likelihood-threshold")
	switch strings.ToLower(value) {
	case "low":
		policy.LikelihoodThreshold = 2
	case "medium":
		policy.LikelihoodThreshold = 3
	case "high":
		policy.LikelihoodThreshold = 4
	default:
		return errors.New("exploit-likelihood-threshold must be one of: low, medium, high")
	}
	return nil
}

func parseRiskThreshold(cmd *cobra.Command) (int, error) {
	value, _ := cmd.Flags().GetString("risk-threshold")
	switch strings.ToLower(value) {
	case "low":
		return 1, nil
	case "medium":
		return 2, nil
	case "high":
		return 3, nil
	case "critical":
		return 4, nil
	}
	return 0, errors.New("valid risk threshold is required")
}

func init() {
	RootCmd.AddCommand(cicheckCmd)
	cicheckCmd.Flags().StringP(
		"risk-threshold", "r", "low", "Risk threshold to fail the command. Available options: low, medium, high, critical")
	cicheckCmd.Flags().Int(
		"health-score-threshold", 0, "Health score threshold (0-100) to pass the command")
	cicheckCmd.Flags().IntP(
		"timeout", "t", 30, "Static scan timeout in minutes for the CI check (default: 30)")

	cicheckCmd.Flags().String(
		"exploit-likelihood-threshold", "",
		"Fail the build on KnoxIQ exploit likelihood. Available options: low, medium, high")

	cicheckCmd.Flags().Bool(
		"include-needs-review", false,
		"Include KnoxIQ needs-review vulnerabilities in the CI check results and build decision")
	viper.BindPFlag(
		"include-needs-review", cicheckCmd.Flags().Lookup("include-needs-review"))
	viper.BindEnv("include-needs-review", "APPKNOX_INCLUDE_NEEDS_REVIEW")
	viper.SetDefault("include-needs-review", false)

	cicheckCmd.Flags().Int(
		"knoxiq-timeout", 30, "KnoxIQ triage timeout in minutes (default: 30)")
	viper.BindPFlag("knoxiq-timeout", cicheckCmd.Flags().Lookup("knoxiq-timeout"))
	viper.BindEnv("knoxiq-timeout", "APPKNOX_KNOXIQ_TIMEOUT")
	viper.SetDefault("knoxiq-timeout", 30)
}
