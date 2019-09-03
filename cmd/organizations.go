package cmd

import (
	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// organizationsCmd represents the organizations command
var organizationsCmd = &cobra.Command{
	Use:   "organizations",
	Short: "List organizations",
	Long:  `List organizations`,
	Run: func(cmd *cobra.Command, args []string) {
		helper.ProcessOrganizations()
	},
}

func init() {
	RootCmd.AddCommand(organizationsCmd)
}
