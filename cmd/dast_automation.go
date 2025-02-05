package cmd

import (
    "errors"
    "fmt"
    "os"
    "strconv"

    "github.com/spf13/cobra"
    "github.com/appknox/appknox-go/helper"
)


var scheduleDastAutomationCmd = &cobra.Command{
    Use:   "schedule-dast-automation <file_id>",
    Short: "Schedule a DAST automation for the specified file",
    Long: `Schedule a new Dynamic Application Security Testing (DAST) automation
for the specified file ID in Appknox. This command enqueues a dynamic scan process.`,

    Args: cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        fileID, err := strconv.Atoi(args[0])
        if err != nil {
            err = errors.New("please enter a valid File ID (integer)")
            helper.PrintError(err)
            os.Exit(1)
        }

        fmt.Printf("Scheduling DAST automation for file: %d\n", fileID)

        // Pass fileID to the helper
        if err := helper.ScheduleDastAutomation(fileID); err != nil {
            errNew := fmt.Errorf("failed to schedule DAST: %v", err)
            helper.PrintError(errNew)
            os.Exit(1)
        }

        fmt.Println("Dynamic scan has been enqueued successfully.")
        return nil
    },
}

func init() {
    RootCmd.AddCommand(scheduleDastAutomationCmd)

}
