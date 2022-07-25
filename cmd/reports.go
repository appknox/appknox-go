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
		allowExperimentalFeatures, _ := cmd.Flags().GetBool("allow-experimental-features")
		outputDir, _ := cmd.Flags().GetString("output")
		generate, _ := cmd.Flags().GetBool("generate")
		// Performing download reports
		ok, err := helper.ProcessDownloadReports(fileID, allowExperimentalFeatures, generate, outputDir)
		if err != nil || !ok {
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(reportsCmd)
	reportsCmd.Flags().StringP("output", "o", ".", "Output directory to save reports")
	reportsCmd.Flags().Bool("generate", false, "Generate reports")
	reportsCmd.Flags().Bool("allow-experimental-features", false, "Allow experimental features to download reports")
}
