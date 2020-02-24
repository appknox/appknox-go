package cmd

import (
	"errors"
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
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("project id is required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		projectID, err := strconv.Atoi(args[0])
		if err != nil {
			helper.PrintError("valid project id is required")
			os.Exit(1)
		}
		versionCode := cmd.Flag("version_code").Value.String()
		offset, _ := cmd.Flags().GetInt("offset")
		limit, _ := cmd.Flags().GetInt("limit")
		helper.ProcessFiles(projectID, versionCode, offset, limit)
	},
}

func init() {
	RootCmd.AddCommand(filesCmd)
	filesCmd.Flags().StringP("version_code", "v", "", "Filter files with version code.")
	filesCmd.Flags().Int("offset", 0, "Filter results with page")
	filesCmd.Flags().Int("limit", 0, "Limit results per page")
}
