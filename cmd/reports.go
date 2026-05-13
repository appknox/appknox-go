package cmd

import (
	"errors"
	"fmt"
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

var reportsCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create Report for the given file ID.",
	Long:  `Create new Report and returns newly created report ID`,
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
		reportId, _, err := helper.ProcessCreateReport(fileID)
		if err != nil {
			helper.PrintError(err)
			return
		}
		fmt.Println(reportId)

	},
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

var reportsDownloadExcelCmd = &cobra.Command{
	Use:   "summary-excel",
	Short: "Download Summary Excel report",
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
			return
		}
		outputFilePath, _ := cmd.Flags().GetString("output")
		if outputFilePath == "" {
			helper.PrintError(errors.New(`Error: Required flag "output" not set`))
			return
		}
		err = helper.ProcessDownloadReportExcel(reportID, outputFilePath)
		if err != nil {
			helper.PrintError(err)
		}
	},
}

var reportsDownloadPdfCmd = &cobra.Command{
	Use:   "pdf <report_id>",
	Short: "Download PDF report",
	Long: `Download a PDF VAPT report along with its password file.

  appknox reports download pdf <report_id>

Files are saved to {output}/{report_id}/report_{report_id}.pdf and report_{report_id}_password.txt.
Default output directory is ./reports/

Use 'appknox reports create <file_id>' to generate a report and get the report ID.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("report id is required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		reportID, err := strconv.Atoi(args[0])
		if err != nil {
			helper.PrintError(errors.New("valid report id is required"))
			return
		}
		outputDir, _ := cmd.Flags().GetString("output")
		if outputDir == "" {
			outputDir = "./reports"
		}
		err = helper.ProcessDownloadReportPDF(reportID, outputDir)
		if err != nil {
			helper.PrintError(err)
		}
	},
}

func init() {
	reportsDownloadCmd.AddCommand(reportsDownloadCsvCmd)
	reportsDownloadCmd.AddCommand(reportsDownloadExcelCmd)
	reportsDownloadCmd.AddCommand(reportsDownloadPdfCmd)
	reportsCmd.AddCommand(reportsDownloadCmd)
	reportsDownloadCmd.PersistentFlags().StringP("output", "o", "", "Output file path to save reports")
	reportsCmd.AddCommand(reportsCreateCmd)
	RootCmd.AddCommand(reportsCmd)
}
