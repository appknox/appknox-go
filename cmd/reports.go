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
	Short: "Vulnerability Analysis Reports",
	Long:  `List, Download, Create reports for the Appknox Files`,
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
			os.Exit(1)
		}
		helper.ProcessListReports(fileID)
	},
}

func init() {
	reportsCmd.AddCommand(reportsListCmd)
	RootCmd.AddCommand(reportsCmd)
	reportsCmd.Flags().StringP("output", "o", ".", "Output directory to save reports")
	reportsCmd.Flags().Bool("generate", false, "Generate reports")
	reportsCmd.Flags().Bool("allow-experimental-features", false, "Allow experimental features to download reports")
}
