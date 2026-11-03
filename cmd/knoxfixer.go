package cmd

import (
	"errors"
	"os"
	"strings"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

var knoxfixerCmd = &cobra.Command{
	Use:   "knoxfixer",
	Short: "Fix KnoxIQ findings in the repository and open / update a pull request.",
	Long: `Applies KnoxIQ remediations to the CI branch and opens (or updates) a pull request
on appknox-knoxfixer/<branch>. Run it after "appknox cicheck" in the same pipeline,
with the file id of that upload (--file-id or APPKNOX_FILE_ID). Needs GITHUB_TOKEN
with contents: write and pull-requests: write.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := parseKnoxFixerOptions(cmd)
		if err != nil {
			helper.PrintError(err)
			os.Exit(1)
		}
		os.Exit(helper.ProcessKnoxFixer(opts))
	},
}

func parseKnoxFixerOptions(cmd *cobra.Command) (helper.KnoxFixerOptions, error) {
	fileID, _ := cmd.Flags().GetInt(flagFileID)
	threshold, _ := cmd.Flags().GetString(flagExploitLikelihoodThreshold)
	verify, _ := cmd.Flags().GetString(flagVerifyCmd)
	appRoot, _ := cmd.Flags().GetString(flagAppRoot)
	threshold = strings.ToLower(strings.TrimSpace(threshold))
	switch threshold {
	case "low", "medium", "high":
	default:
		return helper.KnoxFixerOptions{}, errors.New("exploit-likelihood-threshold must be one of: low, medium, high")
	}
	if fileID < 0 {
		return helper.KnoxFixerOptions{}, errors.New("file-id must be a positive integer")
	}
	return helper.KnoxFixerOptions{
		FileID: fileID, LikelihoodThreshold: threshold, VerifyCmd: verify, AppRoot: appRoot,
	}, nil
}

func init() {
	RootCmd.AddCommand(knoxfixerCmd)
	knoxfixerCmd.Flags().Int(flagFileID, 0,
		"Appknox file id of this build's upload (default: APPKNOX_FILE_ID env)")
	knoxfixerCmd.Flags().String(flagExploitLikelihoodThreshold, "low",
		"Fix KnoxIQ findings at or above this exploit likelihood. Available options: low, medium, high")
	knoxfixerCmd.Flags().String(flagVerifyCmd, "",
		"Optional command to verify the fixes (e.g. \"./gradlew compileDebugKotlin\"); failing fixes are reverted")
	knoxfixerCmd.Flags().String(flagAppRoot, "",
		"Monorepo: app directory relative to the repository root to search for source files")
}
