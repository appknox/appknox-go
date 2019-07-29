package cmd

import (
	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Used to initialize Appknox CLI",
	Long:  `Used to initialize Appknox CLI`,
	Run: func(cmd *cobra.Command, args []string) {
		helper.ProcessInit()
	},
}

func init() {
	RootCmd.AddCommand(initCmd)
}
