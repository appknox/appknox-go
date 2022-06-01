package cmd

import (
	"errors"
	"os"
	"strconv"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// reportsCmd is the command to generate reports
var reportsCmd = &cobra.Command{
	Use:   "reports",
	Short: "Download reports for vulnerabilities check.",
	Long:  `Download reports for all the vulnerabilities check to local system.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("file id is required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Collecting arguments
		fileID, err := strconv.Atoi(args[0])
		if err != nil {
			err := errors.New("Valid file id is required")
			helper.PrintError(err)
			os.Exit(1)
		}
		// Collecting flags
		alwaysApproved, _ := cmd.Flags().GetBool("always-approved")
		outputDir, _ := cmd.Flags().GetString("output")
		// Performing download reports
		helper.ProcessDownloadReports(fileID, alwaysApproved, outputDir)
	},
}

func init() {
	RootCmd.AddCommand(reportsCmd)
	reportsCmd.Flags().StringP("output", "o", ".", "Output directory to save reports")
	reportsCmd.Flags().Bool("always-approved", false, "Need to approve all the reports")
}
