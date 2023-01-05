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

var reportsDownloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download Reports",
	Long:  `Download reports in different formats such as CSV, excel or PDF`,
}

var reportsDownloadCsvCmd = &cobra.Command{
	Use:   "summary-csv",
	Short: "Download Summary CSV report",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("report id is required")
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
	RootCmd.AddCommand(reportsCmd)
}
