package cmd

import (
	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// autofixCmd locates the source file to fix for a finding, client-side.
var autofixCmd = &cobra.Command{
	Use:   "autofix",
	Short: "Locate the source file to fix for a finding (client-side).",
	Long: `Fetch the repository (from a GitHub link with --repo, or an already-checked-out
--repo-path) and locate the single source file that a scan finding points to.

The repository stays on this machine; only model turns route through the Appknox
gateway (which holds the provider key). No provider key is needed here.`,
	Run: func(cmd *cobra.Command, args []string) {
		f := cmd.Flags()
		opts := helper.AutofixOptions{}
		opts.Repo, _ = f.GetString("repo")
		opts.Ref, _ = f.GetString("ref")
		opts.RepoPath, _ = f.GetString("repo-path")
		opts.Finding, _ = f.GetString("finding")
		opts.ClassHint, _ = f.GetString("class-hint")
		opts.FixURL, _ = f.GetString("fix-url")
		opts.FixToken, _ = f.GetString("fix-token")
		opts.GithubToken, _ = f.GetString("github-token")
		helper.ProcessAutofix(opts)
	},
}

func init() {
	RootCmd.AddCommand(autofixCmd)
	f := autofixCmd.Flags()
	f.String("repo", "", "GitHub repo owner/name to auto-fetch (client-side)")
	f.String("ref", "", "Git ref (branch, tag, or SHA); default branch if empty")
	f.String("repo-path", "", "Path to an already-checked-out repo (instead of --repo)")
	f.String("finding", "", "Scan finding detail (required)")
	f.String("class-hint", "", "Class/symbol hint from the finding (optional)")
	f.String("fix-url", "http://localhost:8100", "Appknox fix-service/gateway base URL")
	f.String("fix-token", "", "Scoped fix-service token (or env APPKNOX_AUTOFIX_FIX_TOKEN)")
	f.String("github-token", "", "GitHub token for --repo fetch (or env GITHUB_TOKEN)")
}
