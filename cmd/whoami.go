package cmd

import (
	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// meCmd represents the me command
var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Shows current authenticated user",
	Long:  `Shows current authenticated user`,
	Run: func(cmd *cobra.Command, args []string) {
		helper.ProcessMe()
	},
}

func init() {
	RootCmd.AddCommand(whoamiCmd)
}
