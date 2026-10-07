package cmd

import (
	"fmt"
	"os"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// autofixCmd runs an autofix job: Appknox fixes, this checkout answers.
var autofixCmd = &cobra.Command{
	Use:   "autofix",
	Short: "Apply KnoxIQ remediations to this checkout and open a PR from the base branch.",
	Long: `Start an autofix job for a scanned file on Appknox. Appknox works through
the file's KnoxIQ findings and asks this CLI to read, search and edit files on
the CI checkout (GITHUB_WORKSPACE). Every edit is checked here by the static
patch gate. The fixes are then pushed to a branch off the base branch and a PR
is opened with GITHUB_TOKEN:

  appknox autofix --file-id 118

No prompt, remediation or model runs in CI: only the contents of the files
Appknox asks for leave this machine, and Appknox does not store them.

--risk-threshold defaults to the threshold cicheck used for the same file id
(then APPKNOX_RISK_THRESHOLD, then low); pass it only to override.

APPKNOX_ACCESS_TOKEN is required.`,
	Run: func(cmd *cobra.Command, args []string) {
		f := cmd.Flags()
		opts := helper.AutofixOptions{}
		opts.Ref, _ = f.GetString("ref")
		opts.HeadRef, _ = f.GetString("head-ref")
		opts.Repo, _ = f.GetString("repo")
		opts.RepoPath, _ = f.GetString("repo-path")
		opts.FileID, _ = f.GetInt("file-id")
		opts.GithubToken, _ = f.GetString("github-token")
		opts.DryRun, _ = f.GetBool("dry-run")

		level, name, source, err := autofixRiskThreshold(cmd, opts.FileID)
		if err != nil {
			helper.PrintError(err)
			os.Exit(1)
		}
		opts.RiskThreshold = level
		fmt.Printf("Risk threshold: %s (%s)\n", name, source)

		helper.ProcessAutofix(opts)
	},
}

func init() {
	RootCmd.AddCommand(autofixCmd)
	f := autofixCmd.Flags()
	f.Int("file-id", 0, "Appknox file id whose KnoxIQ findings are fixed (required)")
	f.String("ref", "", "PR base / merge target; CI uses GITHUB_BASE_REF, else the push branch (GITHUB_REF)")
	f.String("head-ref", "", "Feature branch this autofix belongs to (CI: GITHUB_HEAD_REF / GITHUB_REF). All file ids on this branch share one GitHub PR.")
	f.String("repo", "", "GitHub owner/name the PR is opened on (CI: GITHUB_REPOSITORY)")
	f.String("repo-path", "", "Path to the checked-out repo (CI uses GITHUB_WORKSPACE if empty)")
	f.String("github-token", "", "GitHub token for fetching the base and pushing the fix (or env GITHUB_TOKEN)")
	f.Bool("dry-run", false, "Fix and print the diff but do not push a branch")
	f.StringP(
		flagRiskThreshold, "r", "low", "Minimum risk of the findings to fix; defaults to what cicheck used for this file id. Available options: low, medium, high, critical")
}
