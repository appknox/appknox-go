package cmd

import (
	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// autofixCmd locates the source file to fix for a finding, client-side.
var autofixCmd = &cobra.Command{
	Use:   "autofix",
	Short: "Locate the source file to fix for a finding (client-side).",
	Long: `Locate source files for a scan, generate fixes, open a GitHub pull
request, and record it on Appknox. Repo, checkout, and token come from CI
(GITHUB_REPOSITORY, GITHUB_WORKSPACE, GITHUB_TOKEN). The feature branch
(GITHUB_HEAD_REF, or GITHUB_REF on push) names one shared head
appknox-autofix/{feature}; every --file-id on that branch appends a commit
to the same PR. --ref is the PR base (GITHUB_BASE_REF, else the push branch).

On GitHub Actions, set concurrency: autofix-${{ github.head_ref || github.ref_name }}
so parallel file-id jobs do not race the shared ref (the CLI also retries
non-fast-forward pushes). The workflow needs contents: write and
pull-requests: write. Fork PRs are not supported.

The repository stays on this machine; only model turns route through Mycroft
({APPKNOX_API_HOST}/api/knoxiq/autofix/) using APPKNOX_ACCESS_TOKEN. No provider key is needed here.`,
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
	f.Int("file-id", 0, "Appknox file id (fixes every analysis with class hints + remediation)")
	f.String("finding", "", "Manual finding detail (when not using --file-id)")
	f.String("class-hint", "", "Manual class/symbol hint from the finding (optional)")
	f.String("github-token", "", "GitHub token for fetch + push (or env GITHUB_TOKEN)")
	f.Bool("dry-run", false, "Locate + generate the fix but do not push a branch")
	f.String("fix-mode", "agent", "How to generate the fix: 'agent' (default — LLM Edit tool via the agent SDK, no file upload) or 'server' (/v1/fix single-shot, uploads the file)")
	f.Bool("list-analyses", false, "List the file's analyses + derived class hints, then exit (needs --file-id)")
}
