package cmd

import (
	"errors"
	"os"
	"strconv"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// analysesCmd represents the analyses command
var analysesCmd = &cobra.Command{
	Use:   "analyses",
	Short: "List analyses for file",
	Long:  `List analyses for file`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("file id is required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		fileID, err := strconv.Atoi(args[0])
		if err != nil {
			helper.PrintError("valid file id is required")
			os.Exit(1)
		}
		helper.ProcessAnalyses(fileID)
	},
}

func init() {
	RootCmd.AddCommand(analysesCmd)
}
