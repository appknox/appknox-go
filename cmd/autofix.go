package cmd

import (
	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// autofixCmd registers an autofix job, then locates, fixes, and opens a PR.
var autofixCmd = &cobra.Command{
	Use:   "autofix",
	Short: "Register autofix, wait until Processing, then fix on the checkout and open a PR.",
	Long: `With --file-id, register an autofix job on Appknox and wait until it is
Processing. Then locate and fix findings on the CI checkout (GITHUB_WORKSPACE),
push a branch, and open a PR with GITHUB_TOKEN. Recording the PR marks the job
Processed. Model turns go through Appknox (never a provider key):

  appknox autofix --file-id 118

--list-analyses prints analyses for the file, then exits.
--dry-run locates and generates the fix but does not register or push.
--locate-only prints the files each KnoxIQ finding would touch, then exits.

APPKNOX_ACCESS_TOKEN is required.`,
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
		opts.Model, _ = f.GetString("model")
		opts.LocateModel, _ = f.GetString("locate-model")
		opts.DryRun, _ = f.GetBool("dry-run")
		opts.FixMode, _ = f.GetString("fix-mode")
		opts.ListAnalyses, _ = f.GetBool("list-analyses")
		opts.LocateOnly, _ = f.GetBool("locate-only")
		helper.ProcessAutofix(opts)
	},
}

func init() {
	RootCmd.AddCommand(autofixCmd)
	f := autofixCmd.Flags()
	f.String("ref", "", "PR base / merge target; CI uses GITHUB_BASE_REF, else the push branch (GITHUB_REF)")
	f.String("head-ref", "", "Feature branch this autofix belongs to (CI: GITHUB_HEAD_REF / GITHUB_REF). All file ids on this branch share one GitHub PR.")
	f.String("repo-path", "", "Path to an already-checked-out repo (CI uses GITHUB_WORKSPACE if empty)")
	f.Int("file-id", 0, "Appknox file id (register, wait until Processing, then locate + fix on the CI checkout)")
	f.String("finding", "", "Manual finding detail (when not using --file-id)")
	f.String("class-hint", "", "Manual class/symbol hint from the finding (optional)")
	f.String("github-token", "", "GitHub token for fetch + push (or env GITHUB_TOKEN)")
	f.String("model", "", "Model for both turns under --fix-mode agent (blank = the agent default); ignored by --fix-mode server, which takes no model override")
	f.String("locate-model", "", "Model for the locate turn only; falls back to --model. A cheaper model here does not weaken the patch")
	f.Bool("dry-run", false, "Locate + generate the fix but do not push a branch")
	f.String("fix-mode", "agent", "How to generate the fix: 'agent' (default — LLM Edit tool via the agent SDK, no file upload) or 'server' (/v1/fix single-shot, uploads the file)")
	f.Bool("list-analyses", false, "List the file's analyses + derived class hints, then exit (needs --file-id)")
	f.Bool("locate-only", false, "Locate and validate targets per KnoxIQ finding, print them, then exit: no fix, no job registration, no push")
}
