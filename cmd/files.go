package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// filesCmd represents the files command
var filesCmd = &cobra.Command{
	Use:   "files",
	Short: "List files for project",
	Long:  `List files for project`,
	Run: func(cmd *cobra.Command, args []string) {
		projectID, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		versionCode := cmd.Flag("version_code").Value.String()
		offset, _ := RootCmd.Flags().GetInt("offset")
		limit, _ := RootCmd.Flags().GetInt("limit")
		helper.ProcessFiles(projectID, versionCode, offset, limit)
	},
}

func init() {
	RootCmd.AddCommand(filesCmd)
	filesCmd.Flags().StringP("version_code", "v", "", "Filter files with version code.")
}
