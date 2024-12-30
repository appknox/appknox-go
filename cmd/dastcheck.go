package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// dastCheckCmd represents the "dastcheck" command
var dastCheckCmd = &cobra.Command{
	Use:   "dastcheck <file_id>",
	Short: "Check the status of a DAST scan for the specified file",
	Long: `Check the dynamic scan status for the specified file in Appknox.
If the scan is still in progress, this command will poll every 60 seconds.
Once the scan completes or fails, it will display the results or errors.
You can also filter vulnerabilities by using --risk-threshold <int>.`,
	Args: cobra.ExactArgs(1), // exactly 1 argument: file_id
	RunE: func(cmd *cobra.Command, args []string) error {
		fileID, err := strconv.Atoi(args[0])
		if err != nil {
			err := errors.New("Valid file id is required")
			helper.PrintError(err)
			os.Exit(1)
		}
		riskThreshold, _ := cmd.Flags().GetString("risk-threshold")
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

		// Call the single helper function that does everything
		if err := helper.RunDastCheck(fileID, riskThresholdInt); err != nil {
			err = fmt.Errorf("dastcheck command failed: %v", err)
			helper.PrintError(err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	// Assuming your root.go defines var RootCmd = &cobra.Command{...}
	RootCmd.AddCommand(dastCheckCmd)

	// Add the --risk-threshold flag
	dastCheckCmd.Flags().StringP(
		"risk-threshold", "r", "low", "Risk threshold to fail the command. Available options: low, medium, high")
}
