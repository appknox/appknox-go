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

var dastCheckCmd = &cobra.Command{
    Use:   "dastcheck <file_id>",
    Short: "Check the status of a DAST scan for the specified file",
    Long: `Check the dynamic scan status for the specified file in Appknox.
If the scan is still in progress, this command will poll every 60 seconds.
Once the scan completes or fails, it will display the results or errors.
You can also filter vulnerabilities by using --risk-threshold <string>
(low, medium, high, critical).`,

    Args: cobra.ExactArgs(1), // exactly 1 argument: file_id
    RunE: func(cmd *cobra.Command, args []string) error {
        fileID, err := strconv.Atoi(args[0])
        if err != nil {
            helper.PrintError(errors.New("valid file id is required (integer)"))
            os.Exit(1)
        }

        riskInput, _ := cmd.Flags().GetString("risk-threshold")
        riskInputLower := strings.ToLower(riskInput)

        var riskThresholdInt int
        switch riskInputLower {
        case "low":
            riskThresholdInt = 1
        case "medium":
            riskThresholdInt = 2
        case "high":
            riskThresholdInt = 3
        case "critical":
            riskThresholdInt = 4
        default:
            helper.PrintError(errors.New("valid risk threshold is required (low, medium, high, critical)"))
            os.Exit(1)
        }

        err = helper.HandleDynamicScan(fileID, riskThresholdInt)
        if err != nil {
            err = fmt.Errorf("dastcheck command failed: %v", err)
            helper.PrintError(err)
            os.Exit(1)
        }

        return nil
    },
}

func init() {
    RootCmd.AddCommand(dastCheckCmd)

    dastCheckCmd.Flags().StringP(
        "risk-threshold", "r",
        "low",
        "Risk threshold to fail the command. Options: low, medium, high, critical",
    )
}
