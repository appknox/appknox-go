package cmd

import (
	"github.com/appknox/appknox-go/appknox"
	"github.com/spf13/cobra"
)

// logoutCmd represents the logout command
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Delete session credentials",
	Long:  `Delete session credentials`,
	Run: func(cmd *cobra.Command, args []string) {
		appknox.Logout()
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
