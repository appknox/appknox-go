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

// cicheckCmd represents the cicheck command
var cicheckCmd = &cobra.Command{
	Use:   "cicheck",
	Short: "Check for vulnerabilities based on risk threshold.",
	Long:  `List all the vulnerabilities with the risk threshold greater or equal than the provided and fail the command.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("file id is required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		fileID, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		riskThreshold, _ := cmd.Flags().GetString("risk_threshold")
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
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		helper.ProcessCiCheck(fileID, riskThresholdInt)
	},
}

func init() {
	RootCmd.AddCommand(cicheckCmd)
	cicheckCmd.Flags().StringP(
		"risk_threshold", "r", "low", "Risk threshold to fail the command. Available options: low, medium, high")
}
