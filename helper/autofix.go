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
	"github.com/spf13/viper"
)

// AutofixOptions carries the flags for the client-side autofix flow.
type AutofixOptions struct {
	Repo         string // GitHub owner/name to auto-fetch
	Ref          string // git ref (branch/tag/sha); empty = default branch
	RepoPath     string // already-checked-out repo (alternative to Repo)
	FileID       int    // Appknox file id (with AnalysisID → finding + remediation)
	AnalysisID   int    // Appknox analysis id
	Finding      string // manual finding detail (when not using file/analysis id)
	ClassHint    string // manual class/symbol hint
	FixURL       string // Appknox fix-service/gateway base URL
	FixToken     string // scoped fix-service token
	GithubToken  string // GitHub token for the --repo fetch
	DryRun       bool   // locate + fix but do not write the patch
	PushBranch   bool   // push the fix to a new GitHub branch instead of local apply
	ListAnalyses bool   // print the file's analyses + class hints, then exit
	PRNumber     int    // originating pull request; scopes the fix and names the branch
	Scope        string // "pr" (only files changed in PRNumber) or "repo"
}

// autofixDeps are the injectable collaborators (seams for cost-free tests).
type autofixDeps struct {
	locate   func(ctx context.Context, cfg agent.Config, req agent.Request) (string, error)
	fetch    func(ctx context.Context, fileID, analysisID int) (FindingInputs, error)
	agentFix func(ctx context.Context, cfg agent.Config, req agent.FixRequest) (agent.FixResult, error)
	deliver  func(ctx context.Context, opts AutofixOptions, patches []filePatch, inputs FindingInputs) (string, error)
	prFiles  func(ctx context.Context, opts AutofixOptions) ([]string, error)
}

func defaultDeps() autofixDeps {
	return autofixDeps{
		locate:   agent.LocateFile,
		fetch:    fetchAppknoxInputs,
		agentFix: agent.FixFile,
		deliver:  deliverBranch,
		prFiles:  fetchPRFiles,
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
	BranchURL string      // set when --push-branch delivered a branch (compare URL)

	// Verification is KnoxIQ's criteria evaluated against the produced patch.
	// Delivery is gated on it; see VerificationGate.
	Verification VerificationReport

	// OutOfScope lists located files the fix deliberately did NOT touch because
	// they fall outside the pull request being scanned (--scope pr).
	OutOfScope []string
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

// runAutofix: resolve inputs → locate each class → fix each file → deliver.
func runAutofix(ctx context.Context, opts AutofixOptions, d autofixDeps) (Outcome, error) {
	gatewayURL := firstNonEmpty(opts.FixURL, "http://localhost:8100")
	// Gate the endpoint before ANY credential is sent: the id-token exchange
	// below, and every later model turn, carry bearer credentials (CWE-319).
	if err := fixservice.ValidateEndpoint(gatewayURL); err != nil {
		return Outcome{}, err
	}
	// In CI this mints a per-run session token from the runner's OIDC identity,
	// so no long-lived gateway secret has to be stored anywhere.
	token, err := fixservice.ResolveToken(ctx, gatewayURL,
		firstNonEmpty(opts.FixToken, os.Getenv("APPKNOX_AUTOFIX_FIX_TOKEN")),
		viper.GetString("access-token"))
	if err != nil {
		return Outcome{}, err
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

	fixCfg := fixservice.Config{URL: gatewayURL, Token: token}
	return fixSession{opts: opts, d: d, root: root, fixCfg: fixCfg, inputs: inputs}.run(ctx)
}

// fixSession carries the resolved context for locating + fixing one finding's
// (possibly multiple) classes.
type fixSession struct {
	opts   AutofixOptions
	d      autofixDeps
	root   string
	fixCfg fixservice.Config
	inputs FindingInputs
}

// run locates each first-party class, fixes each located file, then delivers.
func (s fixSession) run(ctx context.Context) (Outcome, error) {
	paths, err := s.locateAll(ctx)
	if err != nil {
		return Outcome{}, err
	}
	paths, advisory, err := s.applyScope(ctx, paths)
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{Located: paths, OutOfScope: advisory}
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
				Path: p, Content: res.PatchedContent, Diff: res.Diff})
		}
	}
	// Check the patch against KnoxIQ's own criteria before anything is
	// delivered. A dry run still reports the verdict so the developer sees what
	// a real run would have decided.
	out.Verification = checkCriteria(out.Patches, s.inputs.Criteria)
	if len(out.Patches) == 0 || s.opts.DryRun {
		return out, nil
	}
	if err := VerificationGate(out.Verification, len(s.inputs.Criteria)); err != nil {
		return out, err
	}
	return s.deliver(ctx, out)
}

// locateAll locates the file for each class hint, returning the distinct paths.
func (s fixSession) locateAll(ctx context.Context) ([]string, error) {
	seen := map[string]bool{}
	var paths []string
	for _, hint := range s.inputs.ClassHints {
		p, err := s.d.locate(ctx, agent.Config{FixURL: s.fixCfg.URL, Token: s.fixCfg.Token},
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

// produceFix generates the patch for one file.
//
// The edit happens HERE, on the caller's machine, against the local checkout.
// Only the model turns cross the wire, and they go to Sherrinford, which holds
// the provider key. No file is ever uploaded: the repository does not move, and
// Sherrinford has no endpoint that would accept it.
func (s fixSession) produceFix(ctx context.Context, path string) (agent.FixResult, error) {
	return s.d.agentFix(ctx, agent.Config{FixURL: s.fixCfg.URL, Token: s.fixCfg.Token},
		agent.FixRequest{RepoRoot: s.root, Path: path,
			Finding: s.inputs.Finding, Remediation: s.inputs.Remediation})
}

// deliver pushes all patches to one branch (--push-branch) or applies them locally.
func (s fixSession) deliver(ctx context.Context, out Outcome) (Outcome, error) {
	if s.opts.PushBranch {
		url, err := s.d.deliver(ctx, s.opts, out.Patches, s.inputs)
		if err != nil {
			return out, err
		}
		out.BranchURL = url
		return out, nil
	}
	for i := range out.Patches {
		if err := applyPatch(s.root, out.Patches[i].Path, out.Patches[i].Content); err != nil {
			return out, err
		}
		out.Patches[i].Applied = true
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

// fetchAppknoxInputs resolves the locate + fix inputs for one analysis, taking
// the remediation and the fix criteria from KnoxIQ.
//
// KnoxIQ is the source of truth here, and there is deliberately no fallback: if
// it cannot be reached (after retries) the run FAILS, because a fix built on
// guessed remediation is worse than no fix at all. Reaching KnoxIQ and learning
// that nothing is fixable is a different outcome -- the run abstains with an
// empty Remediation, which downstream renders as advisory-only.
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

	findings, err := fixableKnoxIQFindings(ctx, client, analysisID)
	if err != nil {
		return FindingInputs{}, err
	}
	if len(findings) == 0 {
		// Reached KnoxIQ; it judged nothing worth fixing. Keep the class hints so
		// the run can still report what it would have looked at.
		return FindingInputs{
			Finding:    vuln.Name,
			ClassHints: classHintsFromFindings(findingsText(analysis)),
		}, nil
	}
	return knoxIQInputs(findings, vuln.Name), nil
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
	printOutOfScope(out)
	printVerification(out.Verification)
	printDelivery(opts, out)
}

// printOutOfScope names files that were located but deliberately left alone
// because they fall outside the pull request. Staying silent here would look
// like autofix simply found nothing there.
func printOutOfScope(out Outcome) {
	if len(out.OutOfScope) == 0 {
		return
	}
	fmt.Printf("\nout of scope for this PR (located, not fixed): %s\n",
		strings.Join(out.OutOfScope, ", "))
}

// printVerification renders how the patch fared against KnoxIQ's criteria.
//
// "No criteria" is reported explicitly rather than silently omitted: an unchecked
// patch must never look like a clean one.
func printVerification(report VerificationReport) {
	if len(report.Results) == 0 {
		fmt.Println("\nverification MISSING: KnoxIQ recorded no remediation.verification " +
			"for this finding, so the patch was NOT checked. A real run refuses to " +
			"deliver; re-run the analysis to populate it.")
		return
	}
	fmt.Printf("\nverification: %s\n", report.Summary())
	for _, r := range report.Results {
		fmt.Printf("  [%s] %s\n", r.Status, r.Criterion)
		if r.Detail != "" {
			fmt.Printf("           %s\n", r.Detail)
		}
	}
}

// printDelivery renders the delivery outcome (dry-run / branch / applied).
func printDelivery(opts AutofixOptions, out Outcome) {
	switch {
	case opts.DryRun:
		fmt.Printf("\n[dry-run] not writing %d patched file(s).\n", len(out.Patches))
	case out.BranchURL != "":
		fmt.Printf("\nPushed %d file(s) to a branch — open a PR: %s\n", len(out.Patches), out.BranchURL)
	default:
		fmt.Printf("\nApplied fix to %d file(s): %s\n", len(out.Patches), patchPaths(out.Patches))
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
