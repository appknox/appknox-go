package cmd

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
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
			err := errors.New("Valid file id is required")
			helper.PrintError(err)
			os.Exit(1)
		}
		timeoutMinutes, _ := cmd.Flags().GetInt("timeout")
		timeout := time.Duration(timeoutMinutes) * time.Minute

		healthScoreThreshold, _ := cmd.Flags().GetInt("health-score-threshold")
		riskThreshold, _ := cmd.Flags().GetString("risk-threshold")
		healthScoreChanged := cmd.Flags().Changed("health-score-threshold")
		riskChanged := cmd.Flags().Changed("risk-threshold")

		if healthScoreChanged && riskChanged {
			err := errors.New("only one of risk-threshold or health-score-threshold can be provided")
			helper.PrintError(err)
			os.Exit(1)
		}

		if healthScoreChanged {
			if healthScoreThreshold < 0 || healthScoreThreshold > 100 {
				err := errors.New("health-score-threshold must be between 0 and 100")
				helper.PrintError(err)
				os.Exit(1)
			}
			helper.ProcessHealthScoreCiCheck(fileID, healthScoreThreshold, timeout)
			return
		}

		riskThresholdLower := strings.ToLower(riskThreshold)
		var riskThresholdInt int
		switch riskThresholdStr := riskThresholdLower; riskThresholdStr {
		case "low":
			riskThresholdInt = 1
		case "medium":
			riskThresholdInt = 2
		case "high":
			riskThresholdInt = 3
		case "critical":
			riskThresholdInt = 4
		default:
			err := errors.New("valid risk threshold is required")
			helper.PrintError(err)
			os.Exit(1)
		}
		helper.ProcessCiCheck(fileID, riskThresholdInt, timeout)
	},
}

func init() {
	RootCmd.AddCommand(cicheckCmd)
	cicheckCmd.Flags().StringP(
		"risk-threshold", "r", "low", "Risk threshold to fail the command. Available options: low, medium, high, critical")
	cicheckCmd.Flags().Int(
		"health-score-threshold", 0, "Health score threshold (0-100) to pass the command")
	cicheckCmd.Flags().IntP(
		"timeout", "t", 30, "Static scan timeout in minutes for the CI check (default: 30)")
}
