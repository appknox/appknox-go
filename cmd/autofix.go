package cmd

import (
	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// autofixCmd starts autofix for a file and waits until the PR is recorded.
var autofixCmd = &cobra.Command{
	Use:   "autofix",
	Short: "Start autofix for a file and wait until the PR is raised.",
	Long: `With --file-id, register an autofix job on Appknox and poll
/api/knoxiq/file/{id}/autofix/status/ until the PR is recorded (Processed)
or the job fails. CI stays in a waiting state for the same command:

  appknox autofix --file-id 118

--list-analyses still prints analyses for the file, then exits.
--dry-run and --finding keep the local locate/fix path (no wait).

APPKNOX_ACCESS_TOKEN is required. No provider key is needed here.`,
	Run: func(cmd *cobra.Command, args []string) {
		f := cmd.Flags()
		opts := helper.AutofixOptions{}
		opts.Ref, _ = f.GetString("ref")
		opts.HeadRef, _ = f.GetString("head-ref")
		opts.RepoPath, _ = f.GetString("repo-path")
		opts.FileID, _ = f.GetInt("file-id")
		opts.Finding, _ = f.GetString("finding")
		opts.ClassHint, _ = f.GetString("class-hint")
		opts.GithubToken, _ = f.GetString("github-token")
		opts.DryRun, _ = f.GetBool("dry-run")
		opts.FixMode, _ = f.GetString("fix-mode")
		opts.ListAnalyses, _ = f.GetBool("list-analyses")
		helper.ProcessAutofix(opts)
	},
}

func init() {
	RootCmd.AddCommand(autofixCmd)
	f := autofixCmd.Flags()
	f.String("ref", "", "PR base / merge target; CI uses GITHUB_BASE_REF, else the push branch (GITHUB_REF)")
	f.String("head-ref", "", "Feature branch this autofix belongs to (CI: GITHUB_HEAD_REF / GITHUB_REF). All file ids on this branch share one GitHub PR.")
	f.String("repo-path", "", "Path to an already-checked-out repo (CI uses GITHUB_WORKSPACE if empty)")
	f.Int("file-id", 0, "Appknox file id (start autofix and wait until the PR is raised)")
	f.String("finding", "", "Manual finding detail (when not using --file-id)")
	f.String("class-hint", "", "Manual class/symbol hint from the finding (optional)")
	f.String("github-token", "", "GitHub token for fetch + push (or env GITHUB_TOKEN)")
	f.Bool("dry-run", false, "Locate + generate the fix but do not push a branch")
	f.String("fix-mode", "agent", "How to generate the fix: 'agent' (default — LLM Edit tool via the agent SDK, no file upload) or 'server' (/v1/fix single-shot, uploads the file)")
	f.Bool("list-analyses", false, "List the file's analyses + derived class hints, then exit (needs --file-id)")
}
