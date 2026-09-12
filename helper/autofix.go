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
	Repo         string // GitHub owner/name from CI (GITHUB_REPOSITORY)
	Ref          string // git ref (branch/tag/sha); empty = default branch
	RepoPath     string // already-checked-out repo (CI: GITHUB_WORKSPACE)
	FileID       int    // Appknox file id (with AnalysisID → finding + remediation)
	AnalysisID   int    // Appknox analysis id
	Finding      string // manual finding detail (when not using file/analysis id)
	ClassHint    string // manual class/symbol hint
	FixToken     string // scoped fix-service token
	GithubToken  string // GitHub token for the --repo fetch and branch push
	DryRun       bool   // locate + fix but do not push a branch
	FixMode      string // "server" (default, /v1/fix) or "agent" (client-side Edit, no upload)
	ListAnalyses bool   // print the file's analyses + class hints, then exit
}

// autofixDeps are the injectable collaborators (seams for cost-free tests).
type autofixDeps struct {
	locate      func(ctx context.Context, cfg agent.Config, req agent.Request) (string, error)
	fetch       func(ctx context.Context, fileID, analysisID int) (FindingInputs, error)
	submit      func(ctx context.Context, cfg fixservice.Config, req fixservice.Request) (fixservice.Result, error)
	agentFix    func(ctx context.Context, cfg agent.Config, req agent.FixRequest) (agent.FixResult, error)
	deliver     func(ctx context.Context, opts AutofixOptions, patches []filePatch, inputs FindingInputs) (Delivery, error)
	report      func(ctx context.Context, opts AutofixOptions, d Delivery, patches []filePatch) error
	knoxiqReady func(ctx context.Context, fileID int) error
}

func defaultDeps() autofixDeps {
	return autofixDeps{
		locate:      agent.LocateFile,
		fetch:       fetchAppknoxInputs,
		submit:      fixservice.SubmitAndAwait,
		agentFix:    agent.FixFile,
		deliver:     deliverBranch,
		report:      reportAutofixPR,
		knoxiqReady: checkKnoxIQReady,
	}
}

// filePatch is one located file's generated fix.
type filePatch struct {
	Path       string
	Content    string
	Diff       string
	Confidence float64
	Applied    bool
}

// Outcome is the source-free result of a run — one or more fixed files.
type Outcome struct {
	Located   []string    // every located path
	Patches   []filePatch // per-file fixes that changed something
	BranchURL string      // compare URL after the fix branch is pushed
	CommitSHA string      // git commit SHA of the pushed branch
	Branch    string      // pushed branch name
}

// ProcessAutofix runs the client-side flow and exits non-zero on error.
func ProcessAutofix(opts AutofixOptions) {
	if opts.ListAnalyses {
		if err := checkKnoxIQReady(context.Background(), opts.FileID); err != nil {
			PrintError(err)
			os.Exit(1)
		}
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

// runAutofix: KnoxIQ ready → resolve inputs → locate each class → fix → deliver.
func runAutofix(ctx context.Context, opts AutofixOptions, d autofixDeps) (Outcome, error) {
	if d.knoxiqReady != nil {
		if err := d.knoxiqReady(ctx, opts.FileID); err != nil {
			return Outcome{}, err
		}
	}
	opts = applyCIDefaults(opts)
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

	host, err := resolvedAPIHost()
	if err != nil {
		return Outcome{}, err
	}
	// Same Mycroft host as upload/cicheck. Gate before locate so a
	// plaintext-remote check only on the fix leg cannot leak the token (CWE-319).
	if err := fixservice.ValidateEndpoint(host); err != nil {
		return Outcome{}, err
	}
	return fixSession{opts: opts, d: d, root: root, host: host, token: token, inputs: inputs}.run(ctx)
}

// fixSession carries the resolved context for locating + fixing one finding's
// (possibly multiple) classes.
type fixSession struct {
	opts   AutofixOptions
	d      autofixDeps
	root   string
	host   string
	token  string
	inputs FindingInputs
}

// run locates each first-party class, fixes each located file, then delivers.
func (s fixSession) run(ctx context.Context) (Outcome, error) {
	paths, err := s.locateAll(ctx)
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{Located: paths}
	if len(paths) == 0 || s.inputs.Remediation == "" {
		return out, nil // advisory: nothing located, or locate-only (no remediation)
	}
	for _, p := range paths {
		res, err := s.produceFix(ctx, p)
		if err != nil {
			return out, err
		}
		if res.Changed && res.PatchedContent != "" {
			out.Patches = append(out.Patches, filePatch{
				Path: p, Content: res.PatchedContent, Diff: res.UnifiedDiff, Confidence: res.Confidence})
		}
	}
	if len(out.Patches) == 0 || s.opts.DryRun {
		return out, nil
	}
	return s.deliver(ctx, out)
}

// locateAll locates the file for each class hint, returning the distinct paths.
func (s fixSession) locateAll(ctx context.Context) ([]string, error) {
	seen := map[string]bool{}
	var paths []string
	for _, hint := range s.inputs.ClassHints {
		p, err := s.d.locate(ctx, agent.Config{Host: s.host, Token: s.token},
			agent.Request{RepoRoot: s.root, ClassHint: hint, Finding: s.inputs.Finding})
		if err != nil {
			return nil, err
		}
		if p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// produceFix generates the patch for one file, client-side via the agent's Edit
// tool (--fix-mode agent — NO upload), or server-side via /v1/fix (default).
func (s fixSession) produceFix(ctx context.Context, path string) (fixservice.Result, error) {
	if s.opts.FixMode == "agent" {
		fr, err := s.d.agentFix(ctx, agent.Config{Host: s.host, Token: s.token},
			agent.FixRequest{RepoRoot: s.root, Path: path,
				Finding: s.inputs.Finding, Remediation: s.inputs.Remediation})
		if err != nil {
			return fixservice.Result{}, err
		}
		return fixservice.Result{Changed: fr.Changed, PatchedContent: fr.PatchedContent, UnifiedDiff: fr.Diff}, nil
	}
	content, err := readUnderRoot(s.root, path)
	if err != nil {
		return fixservice.Result{}, err
	}
	return s.d.submit(ctx, fixservice.Config{URL: s.host, Token: s.token}, fixservice.Request{
		Filename: path, FileContent: content, Remediation: s.inputs.Remediation,
		Finding: s.inputs.Finding, Language: detectLanguage(path),
	})
}

// deliver pushes all patches to one GitHub branch and records the delivery on Appknox.
func (s fixSession) deliver(ctx context.Context, out Outcome) (Outcome, error) {
	del, err := s.d.deliver(ctx, s.opts, out.Patches, s.inputs)
	if err != nil {
		return out, err
	}
	out.BranchURL = del.URL
	out.CommitSHA = del.CommitSHA
	out.Branch = del.Branch
	if s.d.report != nil {
		if err := s.d.report(ctx, s.opts, del, out.Patches); err != nil {
			return out, fmt.Errorf("pushed %s but failed to record on Appknox: %w", del.URL, err)
		}
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
	return FindingInputs{Finding: opts.Finding, ClassHints: []string{opts.ClassHint}}, nil
}

// resolveRepoRoot returns the repo root and a cleanup func: a local checkout
// (--repo-path or GITHUB_WORKSPACE), or a freshly fetched GitHub tarball.
func resolveRepoRoot(ctx context.Context, opts AutofixOptions) (string, func(), error) {
	if opts.RepoPath != "" {
		return opts.RepoPath, func() {}, nil
	}
	if opts.Repo == "" {
		return "", nil, errors.New("autofix needs a CI checkout (GITHUB_WORKSPACE) or --repo-path <dir>")
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

// listAnalyses prints each analysis with its first-party classes so the user can
// pick a good autofix target: "+" = single-class (locatable), "*" = multi-class.
func listAnalyses(fileID int) error {
	if fileID <= 0 {
		return errors.New("--list-analyses needs --file-id")
	}
	all, err := allAnalyses(context.Background(), getClient(), fileID)
	if err != nil {
		return err
	}
	for _, a := range all {
		hints := classHintsFromFindings(findingsText(a))
		marker := analysisMarker(len(hints))
		fmt.Printf("%s id=%-6d risk=%-8v vuln=%-4d classes=%v\n",
			marker, a.ID, a.ComputedRisk, a.VulnerabilityID, hints)
	}
	return nil
}

// analysisMarker flags an analysis by its first-party class count.
func analysisMarker(n int) string {
	switch {
	case n > 1:
		return "*" // multi-class
	case n == 1:
		return "+" // single-class
	default:
		return " "
	}
}

// printOutcome renders the run result (one or more files) to stdout.
func printOutcome(opts AutofixOptions, out Outcome) {
	if len(out.Located) == 0 {
		fmt.Println("No source file located for this finding (advisory only).")
		return
	}
	fmt.Printf("Located %d file(s): %s\n", len(out.Located), strings.Join(out.Located, ", "))
	if len(out.Patches) == 0 {
		fmt.Println("No change produced (advisory only).")
		return
	}
	for _, p := range out.Patches {
		fmt.Printf("\n=== %s ===\n", p.Path)
		if p.Confidence > 0 {
			fmt.Printf("confidence: %.2f\n", p.Confidence)
		}
		fmt.Println(p.Diff)
	}
	printDelivery(opts, out)
}

// printDelivery renders the delivery outcome (dry-run or pushed branch).
func printDelivery(opts AutofixOptions, out Outcome) {
	switch {
	case opts.DryRun:
		fmt.Printf("\n[dry-run] not pushing %d patched file(s).\n", len(out.Patches))
	case out.BranchURL != "":
		fmt.Printf("\nPushed %d file(s) to a branch — open a PR: %s\n", len(out.Patches), out.BranchURL)
		if out.CommitSHA != "" {
			fmt.Printf("commit: %s\n", out.CommitSHA)
		}
	default:
		fmt.Printf("\nGenerated fix for %d file(s): %s\n", len(out.Patches), patchPaths(out.Patches))
	}
}

// patchPaths joins the patched file paths for display.
func patchPaths(patches []filePatch) string {
	names := make([]string, len(patches))
	for i, p := range patches {
		names[i] = p.Path
	}
	return strings.Join(names, ", ")
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
