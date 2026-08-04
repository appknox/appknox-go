package cmd

import (
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// sarifCmd represents the sarif command
var sarifCmd = &cobra.Command{
	Use:   "sarif",
	Short: "Create SARIF report",
	Long:  `Create SARIF report`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("file id is required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		fileID, err := strconv.Atoi(args[0])
		if err != nil {
			helper.PrintError("valid file id is required")
			os.Exit(1)
		}
		riskThresholdInt, err := parseRiskThreshold(cmd)
		if err != nil {
			helper.PrintError(err)
			os.Exit(1)
		}
		outputFilePath, _ := cmd.Flags().GetString("output")
		staticMinutes, _ := cmd.Flags().GetInt("timeout")
		knoxiqMinutes, err := knoxIQTimeoutMinutes()
		if err != nil {
			helper.PrintError(err)
			os.Exit(1)
		}
		budget := helper.NewScanBudget(
			time.Duration(staticMinutes)*time.Minute,
			time.Duration(knoxiqMinutes)*time.Minute,
		)
		if err := helper.ConvertToSARIFReport(fileID, riskThresholdInt, outputFilePath, budget); err != nil {
			helper.PrintError(err)
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(sarifCmd)
	sarifCmd.Flags().StringP(
		"risk-threshold", "r", "low", "Minimum risk to include in the report. Available options: low, medium, high, critical")
	sarifCmd.PersistentFlags().StringP("output", "o", "report.sarif", "Output file path to save reports")
	sarifCmd.Flags().IntP(
		"timeout", "t", 30, "Static scan timeout in minutes for the CI check (default: 30)")
}
