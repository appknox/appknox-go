package cmd

import (
	"errors"
	"os"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// uploadCmd represents the upload command
var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload and scan package",
	Long:  `Upload and scan package`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("file path is required")
		}
		fileObj, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer fileObj.Close()
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := os.Open(args[0])
		defer file.Close()
		helper.ProcessUpload(file)
	},
}

func init() {
	RootCmd.AddCommand(uploadCmd)
}
