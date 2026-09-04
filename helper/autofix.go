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
	// AllowUnverified ships a patch KnoxIQ gave us no way to check. Never
	// ships one that demonstrably FAILS a check.
	AllowUnverified bool
	// SourceBranch is the feature branch being remediated. The autofix branch
	// and the PR base both derive from it, so repeated scans of one branch
	// update a single PR instead of opening a new one each time.
	SourceBranch string
	// RiskThreshold is the minimum computed risk worth fixing, matching the
	// severity policy the customer already sets on cicheck.
	RiskThreshold int
}

// autofixDeps are the injectable collaborators (seams for cost-free tests).
type autofixDeps struct {
	locate   func(ctx context.Context, cfg agent.Config, req agent.Request) (string, error)
	fetch    func(ctx context.Context, fileID, analysisID int) (FindingInputs, error)
	agentFix func(ctx context.Context, cfg agent.Config, req agent.FixRequest) (agent.FixResult, error)
	deliver  func(ctx context.Context, opts AutofixOptions, patches []filePatch, inputs FindingInputs) (string, error)
	prFiles  func(ctx context.Context, opts AutofixOptions) ([]string, error)
	// analysisIDs lists the analyses on a file worth attempting.
	analysisIDs func(ctx context.Context, fileID, riskThreshold int) ([]int, error)
}

func defaultDeps() autofixDeps {
	return autofixDeps{
		locate:      agent.LocateFile,
		fetch:       fetchAppknoxInputs,
		agentFix:    agent.FixFile,
		deliver:     deliverBranch,
		prFiles:     fetchPRFiles,
		analysisIDs: locatableAnalysisIDs,
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

	// Analyses records every analysis attempted and what became of it, so a run
	// covering a whole file can say which findings were delivered and which were
	// held back, rather than reporting only the aggregate.
	Analyses []analysisReport
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
	targets, err := resolveTargets(ctx, opts, d)
	if err != nil {
		return Outcome{}, err
	}
	root, cleanup, err := resolveRepoRoot(ctx, opts)
	if err != nil {
		return Outcome{}, err
	}
	defer cleanup()

	fixCfg := fixservice.Config{URL: gatewayURL, Token: token}

	// Every target is attempted, then everything that passed its own gate is
	// delivered together. One branch per scan, not one per finding.
	var out Outcome
	work := newWorkingTree(root)
	for _, t := range targets {
		session := fixSession{opts: opts, d: d, root: root, fixCfg: fixCfg, inputs: t.Inputs, work: work}
		if err := session.attempt(ctx, t, &out); err != nil {
			return out, err
		}
	}
	// One entry per file, carrying every fix applied to it.
	out.Patches = latestPerPath(out.Patches)

	// Fixes are written to the tree as they are produced so each analysis can
	// build on the last. Unless the caller actually wants them applied locally,
	// put the checkout back exactly as we found it.
	if opts.DryRun || opts.PushBranch {
		defer func() { _ = work.restore() }()
	}
	if opts.DryRun || len(out.Patches) == 0 {
		return out, nil
	}
	return deliverAll(ctx, opts, d, root, out, targets)
}

// attempt runs one analysis and folds its result into the aggregate outcome.
//
// A patch that fails its own criteria is held back rather than aborting the
// run: the other findings in the scan are still worth delivering.
func (s fixSession) attempt(ctx context.Context, t analysisTarget, out *Outcome) error {
	produced, err := s.produce(ctx)
	if err != nil {
		return err
	}
	report := analysisReport{
		AnalysisID:      t.AnalysisID,
		Finding:         t.Inputs.Finding,
		Located:         produced.Located,
		Patches:         len(produced.Patches),
		Unfixed:         unfixedPaths(produced.Located, produced.Patches),
		Remediation:     t.Inputs.Remediation,
		DeveloperPrompt: t.Inputs.DeveloperPrompt,
		Verification:    produced.Verification,
	}
	out.Located = append(out.Located, produced.Located...)
	out.OutOfScope = append(out.OutOfScope, produced.OutOfScope...)

	if len(produced.Patches) == 0 {
		report.Skipped = "no change produced"
	} else if err := s.gate(produced.Verification); err != nil {
		report.Skipped = err.Error()
	} else {
		// Land each fix in the tree straight away: the next analysis must see it,
		// or two findings in one file will be fixed against the same original and
		// the later push will discard the earlier one.
		for _, p := range produced.Patches {
			if err := s.work.apply(p.Path, p.Content); err != nil {
				return err
			}
		}
		out.Patches = append(out.Patches, produced.Patches...)
	}
	out.Analyses = append(out.Analyses, report)
	return nil
}

// latestPerPath collapses patches to one entry per file, keeping the newest.
//
// Because each fix was applied to the tree before the next analysis ran, the
// newest content already contains every earlier fix to that file.
func latestPerPath(patches []filePatch) []filePatch {
	index := map[string]int{}
	var out []filePatch
	for _, p := range patches {
		if at, seen := index[p.Path]; seen {
			out[at] = p
			continue
		}
		index[p.Path] = len(out)
		out = append(out, p)
	}
	return out
}

// gate applies the verification gate, honouring --allow-unverified.
func (s fixSession) gate(report VerificationReport) error {
	if s.opts.AllowUnverified {
		return VerificationGateAllowingUnverified(report, len(s.inputs.Criteria))
	}
	return VerificationGate(report, len(s.inputs.Criteria))
}

// deliverAll pushes every verified patch to a single branch and pull request.
func deliverAll(
	ctx context.Context, opts AutofixOptions, d autofixDeps, root string,
	out Outcome, targets []analysisTarget,
) (Outcome, error) {
	inputs := targets[0].Inputs
	if len(targets) > 1 {
		inputs = FindingInputs{Finding: fmt.Sprintf("%d findings", len(out.Analyses))}
	}
	if opts.PushBranch {
		url, err := d.deliver(ctx, opts, out.Patches, inputs)
		if err != nil {
			return out, err
		}
		out.BranchURL = url
		return out, nil
	}
	// Already written to the tree as each analysis produced it; just record it.
	for i := range out.Patches {
		out.Patches[i].Applied = true
	}
	return out, nil
}

// fixSession carries the resolved context for locating + fixing one finding's
// (possibly multiple) classes.
type fixSession struct {
	opts   AutofixOptions
	d      autofixDeps
	root   string
	fixCfg fixservice.Config
	inputs FindingInputs

	// work is shared across analyses so two findings in the same file compose
	// instead of overwriting each other.
	work *workingTree
}

// workingTree tracks edits made during a run so later analyses see earlier
// fixes.
//
// Each analysis fixes a file starting from whatever is on disk. Without this,
// two findings in one file would each be fixed against the ORIGINAL content and
// the second push would silently clobber the first -- which is exactly what
// happened on mfva PR #18, where a crypto fix was lost to a PRNG fix in the same
// file.
type workingTree struct {
	root     string
	original map[string]string // path -> content before we touched it
}

func newWorkingTree(root string) *workingTree {
	return &workingTree{root: root, original: map[string]string{}}
}

// apply writes a patch to the tree, remembering the original content once.
func (w *workingTree) apply(path, content string) error {
	if _, seen := w.original[path]; !seen {
		before, err := readUnderRoot(w.root, path)
		if err != nil {
			return err
		}
		w.original[path] = before
	}
	return applyPatch(w.root, path, content)
}

// restore puts every touched file back, for a dry run that must leave no trace.
func (w *workingTree) restore() error {
	for path, content := range w.original {
		if err := applyPatch(w.root, path, content); err != nil {
			return err
		}
	}
	return nil
}

// produce locates each first-party class, fixes each located file, and checks
// the result against KnoxIQ's criteria. It does NOT deliver: the caller collects
// every analysis first so they can ship as one pull request.
func (s fixSession) produce(ctx context.Context) (Outcome, error) {
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
	// Check the patch against KnoxIQ's own criteria. A dry run reports the
	// verdict too, so the developer sees what a real run would have decided.
	out.Verification = checkCriteria(out.Patches, s.inputs.Criteria)
	return out, nil
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
			Finding: s.inputs.Finding, Remediation: s.inputs.Remediation,
			DeveloperPrompt: s.inputs.DeveloperPrompt, Criteria: s.inputs.Criteria})
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
		// "No change produced" and "changes produced, then withheld" look
		// identical from the patch count and are completely different problems:
		// one sends you to the fixer, the other to the gate. Say which.
		if withheld := patchesWithheld(out); withheld > 0 {
			fmt.Printf("%d fix(es) produced but NOT delivered — see below.\n", withheld)
		} else {
			fmt.Println("No change produced (advisory only).")
		}
		printAnalyses(out, opts.DryRun)
		printOutOfScope(out)
		return
	}
	for _, p := range out.Patches {
		fmt.Printf("\n=== %s ===\n", p.Path)
		if p.Confidence > 0 {
			fmt.Printf("confidence: %.2f\n", p.Confidence)
		}
		fmt.Println(p.Diff)
	}
	printAnalyses(out, opts.DryRun)
	printOutOfScope(out)
	printDelivery(opts, out)
}

// patchesWithheld counts fixes that were generated but held back by a gate.
func patchesWithheld(out Outcome) int {
	var n int
	for _, a := range out.Analyses {
		if a.Skipped != "" {
			n += a.Patches
		}
	}
	return n
}

// printAnalyses reports every analysis attempted and what became of it.
//
// A whole-file run must say which findings were held back and why. Reporting
// only the aggregate would let a partial delivery read as a complete one.
// showRemediation forces the full KnoxIQ guidance to be echoed for every
// analysis. It is printed unconditionally for an analysis that left a located
// file unfixed, because that is when the first question is always "what was the
// fixer actually asked to do?" -- and until now the run never recorded it.
func printAnalyses(out Outcome, showRemediation bool) {
	if len(out.Analyses) == 0 {
		return
	}
	fmt.Printf("\n%d analysis(es) attempted:\n", len(out.Analyses))
	for _, a := range out.Analyses {
		// Report fixed AGAINST located, never fixed alone. A finding covering
		// two files whose fixer edited one is a half-fix, and "1 file(s) fixed"
		// reads exactly like a whole one -- that is how file 348 shipped a
		// Derived Crypto Keys patch for ExportedActivity while the hardcoded DES
		// key in MainActivity went untouched, and the finding never cleared.
		status := fmt.Sprintf("%d of %d located file(s) fixed", a.Patches, len(a.Located))
		if a.Skipped != "" {
			status = "HELD BACK — " + a.Skipped
		}
		fmt.Printf("  [%d] %s: %s\n", a.AnalysisID, a.Finding, status)
		// Name what the fixer declined. Silence here is what made the gap
		// invisible: the file was located, handed to the fixer, and left alone,
		// and no line of output said so.
		if len(a.Unfixed) > 0 {
			fmt.Printf("       NOT FIXED: %s\n", strings.Join(a.Unfixed, ", "))
			fmt.Println("       (located for this finding; the fixer produced no edit)")
		}
		if showRemediation || len(a.Unfixed) > 0 {
			printRemediation(a)
		}
		if len(a.Verification.Results) > 0 {
			fmt.Printf("       verification: %s\n", a.Verification.Summary())
		} else if a.Patches > 0 {
			fmt.Printf("       verification: MISSING — no remediation.verification recorded\n")
		}
	}
}

// printRemediation echoes what KnoxIQ asked for, verbatim.
//
// This is the audit record for a fix: the patch is only judgeable against the
// instruction that produced it, and a fix that looks wrong is often a fix that
// was asked for something different from what the reader assumed. The run used
// to print the diff and the verdict but never the instruction, so "why did it
// not fix that file" had no answer anywhere in the output.
func printRemediation(a analysisReport) {
	if strings.TrimSpace(a.Remediation) == "" {
		fmt.Println("       remediation: NONE RECORDED — KnoxIQ returned no guidance")
		return
	}
	fmt.Println("       --- remediation handed to the fixer ---")
	for _, line := range strings.Split(strings.TrimRight(a.Remediation, "\n"), "\n") {
		fmt.Printf("       | %s\n", line)
	}
	if dp := strings.TrimSpace(a.DeveloperPrompt); dp != "" {
		fmt.Println("       --- KnoxIQ's guidance for the developer ---")
		for _, line := range strings.Split(dp, "\n") {
			fmt.Printf("       | %s\n", line)
		}
	}
}

// unfixedPaths returns the files this analysis located that produced no patch.
//
// Located-but-unfixed is a real outcome, not an anomaly: the fix contract tells
// the model to make NO edit rather than guess when it cannot apply the
// remediation safely, so a declined file is often the correct answer. What is
// not acceptable is doing it quietly -- the finding stays open either way, and
// the reader has to be told which files still carry it.
func unfixedPaths(located []string, patches []filePatch) []string {
	if len(patches) == len(located) {
		return nil
	}
	patched := make(map[string]bool, len(patches))
	for _, p := range patches {
		patched[p.Path] = true
	}
	var unfixed []string
	for _, path := range located {
		if !patched[path] {
			unfixed = append(unfixed, path)
		}
	}
	return unfixed
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
