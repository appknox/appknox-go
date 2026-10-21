package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// autofixCmd registers an autofix job, then locates, fixes, and opens a PR.
var autofixCmd = &cobra.Command{
	Use:   "autofix",
	Short: "Register autofix, wait until Processing, then fix on the checkout and open a PR.",
	Long: `Register an autofix job on Appknox and wait until it is Processing.
Then locate and fix findings on the CI checkout (GITHUB_WORKSPACE), push a
branch, and open a PR with GITHUB_TOKEN. Recording the PR marks the job
Processed. Model turns go through Appknox (never a provider key).

--file-id is optional. When it is omitted, autofix uses the latest file
uploaded for this app on the base branch (--ref, or GITHUB_BASE_REF, else
the branch in GITHUB_REF). The package name and platform are read from the
checkout (Android applicationId or iOS bundle id); pass --package-name and
--platform to override. Upload records that same branch (appknox upload,
from CI or --branch), so a pipeline that uploads a build and a pipeline
that does not both run:

  appknox autofix

The upload, when there is one, has to finish before this step, and it has
to have been made by a CLI that records the branch. Builds uploaded earlier
are not on a branch and are not chosen.

--list-analyses prints analyses for that file, then exits.
--dry-run locates and generates the fix but does not register or push.
--locate-only prints the files each KnoxIQ finding would touch, then exits.

--risk-threshold defaults to the threshold cicheck used for the same file id
(then APPKNOX_RISK_THRESHOLD, then low); pass it only to override.

APPKNOX_ACCESS_TOKEN is required.`,
	Run: func(cmd *cobra.Command, args []string) {
		f := cmd.Flags()
		opts := helper.AutofixOptions{}
		opts.Ref, _ = f.GetString("ref")
		opts.HeadRef, _ = f.GetString("head-ref")
		opts.RepoPath, _ = f.GetString("repo-path")
		opts.FileID, _ = f.GetInt("file-id")
		opts.PackageName, _ = f.GetString("package-name")
		opts.Platform, _ = f.GetString("platform")
		opts.Finding, _ = f.GetString("finding")
		opts.ClassHint, _ = f.GetString("class-hint")
		opts.GithubToken, _ = f.GetString("github-token")
		opts.Model, _ = f.GetString("model")
		opts.LocateModel, _ = f.GetString("locate-model")
		opts.DryRun, _ = f.GetBool("dry-run")
		opts.FixMode, _ = f.GetString("fix-mode")
		opts.ListAnalyses, _ = f.GetBool("list-analyses")
		opts.LocateOnly, _ = f.GetBool("locate-only")

		// An appknox-autofix/ base would start another autofix on a branch this
		// command already created. Print the exception and pass.
		if err := helper.AutofixBranchError(opts); err != nil {
			helper.PrintError(err)
			return
		}
		// Fork pull requests and pull_request_target runs are refused before
		// the job starts, not after the model has worked on their code.
		if err := helper.AutofixEventError(); err != nil {
			helper.PrintError(err)
			os.Exit(1)
		}

		opts, err := helper.EnsureAutofixFile(context.Background(), opts)
		if err != nil {
			helper.PrintError(err)
			os.Exit(1)
		}

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
	f.String("ref", "", "PR base / merge target; CI uses GITHUB_BASE_REF, else the push branch (GITHUB_REF)")
	f.String("head-ref", "", "Feature branch this autofix belongs to (CI: GITHUB_HEAD_REF / GITHUB_REF). All file ids on this branch share one GitHub PR.")
	f.String("repo-path", "", "Path to an already-checked-out repo (CI uses GITHUB_WORKSPACE if empty)")
	f.Int("file-id", 0, "Appknox file id. When omitted, the latest upload on the base branch is used")
	f.String("package-name", "", "Package name or bundle id used to find the latest file. Detected from the checkout when empty")
	f.String("platform", "", "android or ios, used to find the latest file. Detected from the checkout when empty")
	f.String("finding", "", "Manual finding detail (when not using a file id)")
	f.String("class-hint", "", "Manual class/symbol hint from the finding (optional)")
	f.String("github-token", "", "GitHub token for fetch + push (or env GITHUB_TOKEN)")
	f.String("model", "", "Model for both turns under --fix-mode agent (blank = claude-haiku-4-5); ignored by --fix-mode server, which takes no model override")
	f.String("locate-model", "", "Model for the locate turn only; falls back to --model. A cheaper model here does not weaken the patch")
	f.Bool("dry-run", false, "Locate + generate the fix but do not push a branch")
	f.String("fix-mode", "agent", "How to generate the fix: 'agent' (default — LLM Edit tool via the agent SDK, no file upload) or 'server' (/v1/fix single-shot, uploads the file)")
	f.Bool("list-analyses", false, "List the file's analyses + derived class hints, then exit")
	f.Bool("locate-only", false, "Locate and validate targets per KnoxIQ finding, print them, then exit: no fix, no job registration, no push")
	f.StringP(
		flagRiskThreshold, "r", "low", "Minimum risk of the findings to fix; defaults to what cicheck used for this file id. Available options: low, medium, high, critical")
}
