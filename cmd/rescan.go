package cmd

import (
	"github.com/appknox/appknox-go/appknox"
	"github.com/spf13/cobra"
)

// rescanCmd represents the rescan command
var rescanCmd = &cobra.Command{
	Use:   "rescan",
	Short: "Start rescanning a file",
	Long:  `Start rescanning a file`,
	Run: func(cmd *cobra.Command, args []string) {
		appknox.Rescan(args)
	},
}

func init() {
	RootCmd.AddCommand(rescanCmd)
}
