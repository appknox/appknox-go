package cmd

import (
	"errors"
	"strconv"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// reportsCmd is the command to generate reports
var reportsCmd = &cobra.Command{
	Use:   "reports",
	Short: "Vulnerability Analysis Reports",
	Long:  `List or create reports for the file ID. Download reports using report ID`,
}

var reportsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List Vulnerability Analysis Reports",
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
		}
		err = helper.ProcessListReports(fileID)
		if err != nil {
			helper.PrintError(err)
		}
	},
}

var reportsDownloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download Reports",
	Long:  `Download reports in different formats such as CSV, excel or PDF`,
}

var reportsDownloadCsvCmd = &cobra.Command{
	Use:   "summary-csv",
	Short: "List Vulnerability Analysis Reports",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("file id is required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		reportID, err := strconv.Atoi(args[0])
		if err != nil {
			err := errors.New("Valid Report id is required")
			helper.PrintError(err)
		}
		outputFilePath, _ := cmd.Flags().GetString("output")
		err = helper.ProcessDownloadReportCSV(reportID, outputFilePath)
		if err != nil {
			helper.PrintError(err)
		}
	},
}

func init() {
	reportsDownloadCmd.AddCommand(reportsDownloadCsvCmd)
	reportsCmd.AddCommand(reportsDownloadCmd)
	reportsDownloadCmd.PersistentFlags().StringP("output", "o", "", "Output file path to save reports")
	reportsCmd.AddCommand(reportsListCmd)
	RootCmd.AddCommand(reportsCmd)
}
