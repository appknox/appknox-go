package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
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
	PushBranch   bool   // push the fix to a new GitHub branch instead of local apply
	FixMode      string // "server" (default, /v1/fix) or "agent" (client-side Edit, no upload)
	ListAnalyses bool   // print the file's analyses + class hints, then exit
}

// autofixDeps are the injectable collaborators (seams for cost-free tests).
type autofixDeps struct {
	locate   func(ctx context.Context, cfg agent.Config, req agent.Request) (string, error)
	fetch    func(ctx context.Context, fileID, analysisID int) (FindingInputs, error)
	submit   func(ctx context.Context, cfg fixservice.Config, req fixservice.Request) (fixservice.Result, error)
	agentFix func(ctx context.Context, cfg agent.Config, req agent.FixRequest) (agent.FixResult, error)
	deliver  func(ctx context.Context, opts AutofixOptions, path, content string, inputs FindingInputs) (string, error)
}

func defaultDeps() autofixDeps {
	return autofixDeps{
		locate:   agent.LocateFile,
		fetch:    fetchAppknoxInputs,
		submit:   fixservice.SubmitAndAwait,
		agentFix: agent.FixFile,
		deliver:  deliverBranch,
	}
}

// Outcome is the source-free result of a run, for printing/testing.
type Outcome struct {
	Located     bool
	LocatedPath string
	Result      *fixservice.Result // nil in locate-only mode or advisory
	Applied     bool
	BranchURL   string // set when --push-branch delivered a branch (compare URL)
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
	if inputs.Remediation == "" {
		return Outcome{Located: true, LocatedPath: path}, nil // locate-only (no remediation)
	}
	return fixJob{d: d, opts: opts, root: root, path: path, inputs: inputs, fixCfg: fixCfg}.generate(ctx)
}

// fixJob carries the resolved context for the fix-generate-and-deliver tail.
type fixJob struct {
	d      autofixDeps
	opts   AutofixOptions
	root   string
	path   string
	inputs FindingInputs
	fixCfg fixservice.Config
}

// generate produces the patch (agent or server) and delivers it.
func (j fixJob) generate(ctx context.Context) (Outcome, error) {
	out := Outcome{Located: true, LocatedPath: j.path}
	res, err := j.produceFix(ctx)
	if err != nil {
		return out, err
	}
	out.Result = &res
	if !res.Changed || res.PatchedContent == "" || j.opts.DryRun {
		return out, nil // no change / empty / dry-run → nothing to deliver
	}
	return j.deliverOrApply(ctx, out, res.PatchedContent)
}

// produceFix generates the patch client-side via the agent's Edit tool
// (--fix-mode agent — NO file uploaded), or server-side via /v1/fix (default).
func (j fixJob) produceFix(ctx context.Context) (fixservice.Result, error) {
	if j.opts.FixMode == "agent" {
		fr, err := j.d.agentFix(ctx, agent.Config{FixURL: j.fixCfg.URL, Token: j.fixCfg.Token},
			agent.FixRequest{RepoRoot: j.root, Path: j.path,
				Finding: j.inputs.Finding, Remediation: j.inputs.Remediation})
		if err != nil {
			return fixservice.Result{}, err
		}
		return fixservice.Result{Changed: fr.Changed, PatchedContent: fr.PatchedContent, UnifiedDiff: fr.Diff}, nil
	}
	content, err := readUnderRoot(j.root, j.path)
	if err != nil {
		return fixservice.Result{}, err
	}
	return j.d.submit(ctx, j.fixCfg, fixservice.Request{
		Filename: j.path, FileContent: content, Remediation: j.inputs.Remediation,
		Finding: j.inputs.Finding, Language: detectLanguage(j.path),
	})
}

// deliverOrApply pushes a branch (--push-branch) or writes the patch locally.
func (j fixJob) deliverOrApply(ctx context.Context, out Outcome, content string) (Outcome, error) {
	if j.opts.PushBranch {
		url, err := j.d.deliver(ctx, j.opts, j.path, content, j.inputs)
		if err != nil {
			return out, err
		}
		out.BranchURL = url
		return out, nil
	}
	if err := applyPatch(j.root, j.path, content); err != nil {
		return out, err
	}
	out.Applied = true
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
	if out.Result.Confidence > 0 {
		fmt.Printf("\nconfidence: %.2f\n", out.Result.Confidence)
	}
	fmt.Printf("\n%s\n", out.Result.UnifiedDiff)
	if opts.DryRun {
		fmt.Println("[dry-run] not writing the patched file.")
		return
	}
	if out.BranchURL != "" {
		fmt.Println("Pushed fix branch — open a PR:", out.BranchURL)
		return
	}
	if out.Applied {
		fmt.Println("Applied fix to", out.LocatedPath)
	}
}

// repoComponentRE is GitHub's owner/repo charset — rejects "/", "?", spaces, etc.
// so a --repo value can never inject extra URL path/query segments (CWE-20).
var repoComponentRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// splitRepo parses and validates an "owner/name" repo spec.
func splitRepo(spec string) (string, string, error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 || !repoComponentRE.MatchString(parts[0]) || !repoComponentRE.MatchString(parts[1]) {
		return "", "", fmt.Errorf("invalid --repo %q, expected owner/name (letters, digits, . _ -)", spec)
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
