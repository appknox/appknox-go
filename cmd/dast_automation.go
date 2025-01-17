package cmd

import (
    "errors"
    "fmt"
    "os"
    "strconv"

    "github.com/spf13/cobra"
    "github.com/appknox/appknox-go/helper"
)

// We'll store user input for --enable-api-capture
var enableAPICapture bool

// Also allow the user to override mode from CLI, if needed. By default, "1" = Automated
var dastMode int

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

        // Show a quick message
        fmt.Printf("Scheduling DAST automation for file: %d\n", fileID)
        fmt.Printf("Mode: %d (1=Automated)\n", dastMode)
        fmt.Printf("API Capture enabled: %v\n", enableAPICapture)

        // Pass fileID + mode + enableAPICapture to the helper
        if err := helper.ScheduleDastAutomation(fileID, dastMode, enableAPICapture); err != nil {
            errNew := fmt.Errorf("failed to schedule DAST: %v", err)
            helper.PrintError(errNew)
            os.Exit(1)
        }

        fmt.Println("Dynamic scan has been inqueued successfully.")
        return nil
    },
}

func init() {
    RootCmd.AddCommand(scheduleDastAutomationCmd)

    // Add the --enable-api-capture bool flag (default false)
    scheduleDastAutomationCmd.Flags().BoolVar(
        &enableAPICapture,
        "enable-api-capture",
        false,
        "Set to true or false to enable API capture for the dynamic scan",
    )

    // Add an optional --mode int flag (default 1) to represent "automated"=1, "manual"=0, etc.
    scheduleDastAutomationCmd.Flags().IntVar(
        &dastMode,
        "mode",
        1,
        "Mode for the DAST scan (1=Automated, 0=Manual, etc.)",
    )
}
