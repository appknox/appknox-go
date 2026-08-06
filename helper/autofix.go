package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/appknox/appknox-go/agent"
	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/fixservice"
	"github.com/appknox/appknox-go/ghfetch"
)

// AutofixOptions carries the flags for the client-side autofix flow.
type AutofixOptions struct {
	Repo        string // GitHub owner/name to auto-fetch
	Ref         string // git ref (branch/tag/sha); empty = default branch
	RepoPath    string // already-checked-out repo (alternative to Repo)
	FileID      int    // Appknox file id (with AnalysisID → finding + remediation)
	AnalysisID  int    // Appknox analysis id
	Finding     string // manual finding detail (when not using file/analysis id)
	ClassHint   string // manual class/symbol hint
	FixURL      string // Appknox fix-service/gateway base URL
	FixToken     string // scoped fix-service token
	GithubToken  string // GitHub token for the --repo fetch
	DryRun       bool   // locate + fix but do not write the patch
	ListAnalyses bool   // print the file's analyses + class hints, then exit
}

// autofixDeps are the injectable collaborators (seams for cost-free tests).
type autofixDeps struct {
	locate func(ctx context.Context, cfg agent.Config, req agent.Request) (string, error)
	fetch  func(ctx context.Context, fileID, analysisID int) (FindingInputs, error)
	submit func(ctx context.Context, cfg fixservice.Config, req fixservice.Request) (fixservice.Result, error)
}

func defaultDeps() autofixDeps {
	return autofixDeps{
		locate: agent.LocateFile,
		fetch:  fetchAppknoxInputs,
		submit: fixservice.SubmitAndAwait,
	}
}

// Outcome is the source-free result of a run, for printing/testing.
type Outcome struct {
	Located     bool
	LocatedPath string
	Result      *fixservice.Result // nil in locate-only mode or advisory
	Applied     bool
}

// ProcessAutofix runs the client-side flow and exits non-zero on error.
func ProcessAutofix(opts AutofixOptions) {
	if opts.ListAnalyses {
		if err := listAnalyses(opts.FileID); err != nil {
			PrintError(err)
			os.Exit(1)
		}
		return
	}
	out, err := runAutofix(context.Background(), opts, defaultDeps())
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	printOutcome(opts, out)
}

// runAutofix: resolve inputs → fetch/locate → read → /v1/fix → apply (or dry-run).
func runAutofix(ctx context.Context, opts AutofixOptions, d autofixDeps) (Outcome, error) {
	token := firstNonEmpty(opts.FixToken, os.Getenv("APPKNOX_AUTOFIX_FIX_TOKEN"))
	if token == "" {
		return Outcome{}, errors.New("fix-service token required (--fix-token or APPKNOX_AUTOFIX_FIX_TOKEN)")
	}
	inputs, err := resolveInputs(ctx, opts, d.fetch)
	if err != nil {
		return Outcome{}, err
	}
	root, cleanup, err := resolveRepoRoot(ctx, opts)
	if err != nil {
		return Outcome{}, err
	}
	defer cleanup()

	fixCfg := fixservice.Config{URL: firstNonEmpty(opts.FixURL, "http://localhost:8100"), Token: token}
	// Gate the endpoint before ANY call: locate routes the same token+prompt
	// through this URL first, so a plaintext-remote check only on the fix leg
	// would still leak the token during locate (CWE-319).
	if err := fixservice.ValidateEndpoint(fixCfg.URL); err != nil {
		return Outcome{}, err
	}
	path, err := d.locate(ctx, agent.Config{FixURL: fixCfg.URL, Token: token},
		agent.Request{RepoRoot: root, ClassHint: inputs.ClassHint, Finding: inputs.Finding})
	if err != nil {
		return Outcome{}, err
	}
	if path == "" {
		return Outcome{}, nil // abstain → advisory only
	}
	out := Outcome{Located: true, LocatedPath: path}
	if inputs.Remediation == "" {
		return out, nil // locate-only (no analysis → no remediation → cannot fix)
	}
	content, err := readUnderRoot(root, path)
	if err != nil {
		return out, err
	}
	res, err := d.submit(ctx, fixCfg, fixservice.Request{
		Filename: path, FileContent: content, Remediation: inputs.Remediation,
		Finding: inputs.Finding, Language: detectLanguage(path),
	})
	if err != nil {
		return out, err
	}
	out.Result = &res
	// Never overwrite the source with empty content, even if changed=true.
	if res.Changed && res.PatchedContent != "" && !opts.DryRun {
		if err := applyPatch(root, path, res.PatchedContent); err != nil {
			return out, err
		}
		out.Applied = true
	}
	return out, nil
}

// resolveInputs derives finding/hint/remediation from Appknox ids, or the flags.
func resolveInputs(
	ctx context.Context, opts AutofixOptions,
	fetch func(context.Context, int, int) (FindingInputs, error),
) (FindingInputs, error) {
	if opts.FileID > 0 && opts.AnalysisID > 0 {
		return fetch(ctx, opts.FileID, opts.AnalysisID)
	}
	if opts.Finding == "" {
		return FindingInputs{}, errors.New("provide --file-id + --analysis-id, or --finding")
	}
	return FindingInputs{Finding: opts.Finding, ClassHint: opts.ClassHint}, nil
}

// resolveRepoRoot returns the repo root and a cleanup func: a local --repo-path,
// or a freshly fetched GitHub tarball (cleanup removes the temp dir).
func resolveRepoRoot(ctx context.Context, opts AutofixOptions) (string, func(), error) {
	if opts.RepoPath != "" {
		return opts.RepoPath, func() {}, nil
	}
	if opts.Repo == "" {
		return "", nil, errors.New("provide --repo owner/name (auto-fetch) or --repo-path <dir>")
	}
	owner, name, err := splitRepo(opts.Repo)
	if err != nil {
		return "", nil, err
	}
	return ghfetch.FetchTarball(ctx, ghfetch.Config{
		Owner: owner, Repo: name, Ref: opts.Ref,
		Token: firstNonEmpty(opts.GithubToken, os.Getenv("GITHUB_TOKEN")),
	})
}

// fetchAppknoxInputs pulls the analysis + vulnerability (KnoxIQ) and derives the
// source-free finding/hint/remediation.
func fetchAppknoxInputs(ctx context.Context, fileID, analysisID int) (FindingInputs, error) {
	client := getClient()
	analysis, err := findAnalysis(ctx, client, fileID, analysisID)
	if err != nil {
		return FindingInputs{}, err
	}
	vuln, _, err := client.Vulnerabilities.GetByID(ctx, analysis.VulnerabilityID)
	if err != nil {
		return FindingInputs{}, err
	}
	return deriveFindingInputs(analysis, vuln), nil
}

// allAnalyses fetches every analysis for a file (count, then the full list).
func allAnalyses(ctx context.Context, client *appknox.Client, fileID int) ([]*appknox.Analysis, error) {
	_, resp, err := client.Analyses.ListByFile(ctx, fileID, nil)
	if err != nil {
		return nil, err
	}
	opt := &appknox.AnalysisListOptions{ListOptions: appknox.ListOptions{Limit: resp.GetCount()}}
	all, _, err := client.Analyses.ListByFile(ctx, fileID, opt)
	return all, err
}

// findAnalysis returns the analysis matching analysisID for the file.
func findAnalysis(ctx context.Context, client *appknox.Client, fileID, analysisID int) (*appknox.Analysis, error) {
	all, err := allAnalyses(ctx, client, fileID)
	if err != nil {
		return nil, err
	}
	for _, a := range all {
		if a.ID == analysisID {
			return a, nil
		}
	}
	return nil, fmt.Errorf("analysis %d not found for file %d", analysisID, fileID)
}

// listAnalyses prints each analysis with its derived class hint ("*" marks the
// locatable ones), so the user can pick a good autofix target.
func listAnalyses(fileID int) error {
	if fileID <= 0 {
		return errors.New("--list-analyses needs --file-id")
	}
	all, err := allAnalyses(context.Background(), getClient(), fileID)
	if err != nil {
		return err
	}
	for _, a := range all {
		hint := classHintFromFindings(findingsText(a))
		marker := " "
		if hint != "" {
			marker = "*"
		}
		fmt.Printf("%s id=%-6d risk=%-8v vuln=%-4d hint=%q\n",
			marker, a.ID, a.ComputedRisk, a.VulnerabilityID, hint)
	}
	return nil
}

// printOutcome renders the run result to stdout.
func printOutcome(opts AutofixOptions, out Outcome) {
	if !out.Located {
		fmt.Println("No source file located for this finding (advisory only).")
		return
	}
	fmt.Println("Located file to fix:", out.LocatedPath)
	if out.Result == nil {
		return // locate-only mode
	}
	if !out.Result.Changed {
		fmt.Println("Fix service returned no change (advisory only).")
		return
	}
	fmt.Printf("\nconfidence: %.2f\n\n%s\n", out.Result.Confidence, out.Result.UnifiedDiff)
	if opts.DryRun {
		fmt.Println("[dry-run] not writing the patched file.")
		return
	}
	if out.Applied {
		fmt.Println("Applied fix to", out.LocatedPath)
	}
}

// splitRepo parses an "owner/name" repo spec.
func splitRepo(spec string) (string, string, error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid --repo %q, expected owner/name", spec)
	}
	return parts[0], parts[1], nil
}

// firstNonEmpty returns a if non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
