package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	// Import your helper package
	"github.com/appknox/appknox-go/helper"
)

// scheduleDastAutomationCmd represents the schedule DAST automation command
var scheduleDastAutomationCmd = &cobra.Command{
	Use:   "schedule-dast-automation <file_id>",
	Short: "Schedule a DAST automation for the specified file",
	Long: `Schedule a new Dynamic Application Security Testing (DAST) automation
for the specified file ID in Appknox. This command enqueues a dynamic scan process.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fileID, err := strconv.Atoi(args[0])
		if err != nil {
			err = errors.New("please enter a valid File ID")
			helper.PrintError(err)
			os.Exit(1)
		}

		// Optionally print an initial message
		fmt.Printf("Scheduling DAST automation for file: %d\n", fileID)

		// Call the helper method — it handles client creation & API call
		if err := helper.ScheduleDastAutomation(fileID); err != nil {
			errNew := fmt.Errorf("failed to schedule DAST: %v", err)
			helper.PrintError(errNew)
			os.Exit(1)
		}

		fmt.Println("Dynamic scan has been inqueued successfully.")
		return nil
	},
}

func init() {
	// Attach to your root command; change `RootCmd` to `rootCmd` if your root is lowercase.
	RootCmd.AddCommand(scheduleDastAutomationCmd)
}
