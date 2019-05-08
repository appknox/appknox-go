package cmd

import (
	"github.com/appknox/appknox-go/appknox"
	"github.com/spf13/cobra"
)

// uploadCmd represents the upload command
var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload and scan package",
	Long:  `Upload and scan package`,
	Run: func(cmd *cobra.Command, args []string) {
		appknox.Upload(args)
	},
}

func init() {
	rootCmd.AddCommand(uploadCmd)
}
