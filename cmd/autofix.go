package cmd

import (
	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// autofixCmd locates the source file to fix for a finding, client-side.
var autofixCmd = &cobra.Command{
	Use:   "autofix",
	Short: "Locate the source file to fix for a finding (client-side).",
	Long: `Locate the source file for a scan finding, generate a fix, and push it to a
new GitHub branch. Repo, checkout, token, and source PR come from CI
(GITHUB_REPOSITORY, GITHUB_WORKSPACE, GITHUB_TOKEN, GITHUB_REF / event payload).
When --file-id and --analysis-id are set, the delivery is recorded on Appknox.

The repository stays on this machine; only model turns route through the Appknox
gateway (which holds the provider key). No provider key is needed here.`,
	Run: func(cmd *cobra.Command, args []string) {
		f := cmd.Flags()
		opts := helper.AutofixOptions{}
		opts.Ref, _ = f.GetString("ref")
		opts.RepoPath, _ = f.GetString("repo-path")
		opts.FileID, _ = f.GetInt("file-id")
		opts.AnalysisID, _ = f.GetInt("analysis-id")
		opts.Finding, _ = f.GetString("finding")
		opts.ClassHint, _ = f.GetString("class-hint")
		opts.FixToken, _ = f.GetString("fix-token")
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
	f.String("ref", "", "Git ref (branch, tag, or SHA); CI uses GITHUB_BASE_REF if empty")
	f.String("repo-path", "", "Path to an already-checked-out repo (CI uses GITHUB_WORKSPACE if empty)")
	f.Int("file-id", 0, "Appknox file id (with --analysis-id → finding + KnoxIQ remediation)")
	f.Int("analysis-id", 0, "Appknox analysis id")
	f.String("finding", "", "Manual finding detail (when not using --file-id/--analysis-id)")
	f.String("class-hint", "", "Manual class/symbol hint from the finding (optional)")
	f.String("fix-token", "", "Scoped fix-service token (or env APPKNOX_AUTOFIX_FIX_TOKEN)")
	f.String("github-token", "", "GitHub token for fetch + push (or env GITHUB_TOKEN)")
	f.Bool("dry-run", false, "Locate + generate the fix but do not push a branch")
	f.String("fix-mode", "agent", "How to generate the fix: 'agent' (default — LLM Edit tool via the agent SDK, no file upload) or 'server' (/v1/fix single-shot, uploads the file)")
	f.Bool("list-analyses", false, "List the file's analyses + derived class hints, then exit (needs --file-id)")
}
