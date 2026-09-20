package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/appknox/appknox-go/agent"
	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/fixservice"
	"github.com/appknox/appknox-go/ghfetch"
	"github.com/spf13/viper"
)

var (
	autofixPollInterval = 5 * time.Second
	autofixHardLimit    = time.Hour
	autofixSleep        = time.Sleep
)

// AutofixOptions carries the flags for the client-side autofix flow.
type AutofixOptions struct {
	Repo         string // GitHub owner/name from CI (GITHUB_REPOSITORY)
	Ref          string // PR base / merge target; empty = repo default branch
	HeadRef      string // feature branch this autofix belongs to (CI: GITHUB_HEAD_REF / GITHUB_REF)
	RepoPath     string // already-checked-out repo (CI: GITHUB_WORKSPACE)
	FileID       int    // Appknox file id (every fixable analysis on the file)
	Finding      string // manual finding detail (when not using file id)
	ClassHint    string // manual class/symbol hint
	GithubToken  string // GitHub token for the --repo fetch and branch push
	DryRun       bool   // locate + fix but do not push a branch
	FixMode      string // "server" (default, /v1/fix) or "agent" (client-side Edit, no upload)
	ListAnalyses bool   // print the file's analyses + class hints, then exit
}

// autofixDeps are the injectable collaborators (seams for cost-free tests).
type autofixDeps struct {
	locate      func(ctx context.Context, cfg agent.Config, req agent.Request) (string, error)
	fetch       func(ctx context.Context, fileID int) ([]FindingInputs, error)
	submit      func(ctx context.Context, cfg fixservice.Config, req fixservice.Request) (fixservice.Result, error)
	agentFix    func(ctx context.Context, cfg agent.Config, req agent.FixRequest) (agent.FixResult, error)
	deliver     func(ctx context.Context, opts AutofixOptions, patches []filePatch) (Delivery, error)
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
	Finding    string
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
	// CI / --file-id waits on Mycroft until the autofix PR is recorded.
	// --dry-run and manual --finding keep the local locate/fix path.
	if opts.FileID > 0 && !opts.DryRun {
		if err := processAutofixWait(context.Background(), opts.FileID); err != nil {
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

func processAutofixWait(ctx context.Context, fileID int) error {
	ctx, cancel := context.WithTimeout(ctx, autofixHardLimit)
	defer cancel()
	if err := checkKnoxIQReady(ctx, fileID); err != nil {
		if isAutofixTimeout(ctx, err) {
			return autofixTimeoutError(fileID)
		}
		return err
	}
	return awaitAutofix(ctx, getClient(), fileID)
}

func awaitAutofix(ctx context.Context, client *appknox.Client, fileID int) error {
	if client == nil {
		return fmt.Errorf("autofix start failed: missing Appknox client")
	}
	started, _, err := client.KnoxIQ.StartAutofix(ctx, fileID)
	if err != nil {
		if isAutofixTimeout(ctx, err) {
			reportAutofixTimeout(client, fileID)
			return autofixTimeoutError(fileID)
		}
		return fmt.Errorf("autofix start failed: %w", err)
	}
	fmt.Println("\nAutofix status:")
	return pollAutofix(ctx, client, fileID, started)
}

func pollAutofix(ctx context.Context, client *appknox.Client, fileID int, current *appknox.AutofixRequest) error {
	last := ""
	for {
		if current == nil {
			return fmt.Errorf("autofix status missing for file %d", fileID)
		}
		if current.Status != last {
			fmt.Printf("  %s\n", current.Status)
			last = current.Status
		}
		switch current.Status {
		case appknox.AutofixStatusProcessed:
			if current.PRURL != "" {
				fmt.Printf("Opened PR: %s\n", current.PRURL)
			}
			return nil
		case appknox.AutofixStatusErrored:
			msg := current.ErrorMessage
			if msg == "" {
				msg = "autofix failed"
			}
			return fmt.Errorf("autofix errored for file %d: %s", fileID, msg)
		case appknox.AutofixStatusTimedOut:
			return autofixTimeoutError(fileID)
		}
		if err := ctx.Err(); err != nil {
			reportAutofixTimeout(client, fileID)
			return autofixTimeoutError(fileID)
		}
		autofixSleep(autofixPollInterval)
		if err := ctx.Err(); err != nil {
			reportAutofixTimeout(client, fileID)
			return autofixTimeoutError(fileID)
		}
		next, _, err := client.KnoxIQ.GetAutofixStatus(ctx, fileID)
		if err != nil {
			if isAutofixTimeout(ctx, err) {
				reportAutofixTimeout(client, fileID)
				return autofixTimeoutError(fileID)
			}
			return fmt.Errorf("autofix status check failed: %w", err)
		}
		current = next
	}
}

func isAutofixTimeout(ctx context.Context, err error) bool {
	return errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
}

func autofixTimeoutError(fileID int) error {
	return fmt.Errorf("autofix timed out for file %d after %s", fileID, autofixHardLimit)
}

func reportAutofixTimeout(client *appknox.Client, fileID int) {
	if client == nil {
		return
	}
	_, _, _ = client.KnoxIQ.MarkAutofixTimedOut(context.Background(), fileID)
}

// runAutofix: KnoxIQ ready → resolve inputs → locate each class → fix → deliver.
func runAutofix(ctx context.Context, opts AutofixOptions, d autofixDeps) (Outcome, error) {
	if d.knoxiqReady != nil {
		if err := d.knoxiqReady(ctx, opts.FileID); err != nil {
			return Outcome{}, err
		}
	}
	opts = applyCIDefaults(opts)
	token := viper.GetString("access-token")
	if token == "" {
		return Outcome{}, errors.New("autofix needs an Appknox access token (--access-token or APPKNOX_ACCESS_TOKEN)")
	}
	findings, err := resolveInputs(ctx, opts, d.fetch)
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
	return fixSession{opts: opts, d: d, root: root, host: host, token: token, findings: findings}.run(ctx)
}

// fixSession carries the resolved context for locating + fixing every finding
// on a file (or one manual --finding).
type fixSession struct {
	opts     AutofixOptions
	d        autofixDeps
	root     string
	host     string
	token    string
	findings []FindingInputs
}

// run locates and fixes each finding, then delivers every patch on one branch.
func (s fixSession) run(ctx context.Context) (Outcome, error) {
	out := Outcome{}
	located := map[string]bool{}
	patched := map[string]bool{}
	for _, in := range s.findings {
		paths, err := s.locateAll(ctx, in)
		if err != nil {
			if s.opts.FileID <= 0 {
				return Outcome{}, err
			}
			fmt.Printf("autofix: skipping %q: %v\n", in.Finding, err)
			continue
		}
		for _, p := range paths {
			if !located[p] {
				located[p] = true
				out.Located = append(out.Located, p)
			}
		}
		if len(paths) == 0 || in.Remediation == "" {
			continue
		}
		for _, p := range paths {
			if patched[p] {
				continue
			}
			res, err := s.produceFix(ctx, p, in)
			if err != nil {
				if s.opts.FileID <= 0 {
					return out, err
				}
				fmt.Printf("autofix: skipping %s for %q: %v\n", p, in.Finding, err)
				continue
			}
			if res.Changed && res.PatchedContent != "" {
				patched[p] = true
				out.Patches = append(out.Patches, filePatch{
					Path: p, Content: res.PatchedContent, Diff: res.UnifiedDiff,
					Confidence: res.Confidence, Finding: in.Finding,
				})
			}
		}
	}
	if len(out.Patches) == 0 || s.opts.DryRun {
		return out, nil
	}
	return s.deliver(ctx, out)
}

// locateAll locates the file for each class hint, returning the distinct paths.
func (s fixSession) locateAll(ctx context.Context, in FindingInputs) ([]string, error) {
	seen := map[string]bool{}
	var paths []string
	for _, hint := range in.ClassHints {
		p, err := s.d.locate(ctx, agent.Config{Host: s.host, Token: s.token},
			agent.Request{RepoRoot: s.root, ClassHint: hint, Finding: in.Finding})
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
func (s fixSession) produceFix(ctx context.Context, path string, in FindingInputs) (fixservice.Result, error) {
	if s.opts.FixMode == "agent" {
		fr, err := s.d.agentFix(ctx, agent.Config{Host: s.host, Token: s.token},
			agent.FixRequest{RepoRoot: s.root, Path: path,
				Finding: in.Finding, Remediation: in.Remediation})
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
		Filename: path, FileContent: content, Remediation: in.Remediation,
		Finding: in.Finding, Language: detectLanguage(path),
	})
}

// deliver pushes all patches to one GitHub branch and records the delivery on Appknox.
func (s fixSession) deliver(ctx context.Context, out Outcome) (Outcome, error) {
	del, err := s.d.deliver(ctx, s.opts, out.Patches)
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
	fetch func(context.Context, int) ([]FindingInputs, error),
) ([]FindingInputs, error) {
	if opts.FileID > 0 {
		return fetch(ctx, opts.FileID)
	}
	if opts.Finding == "" {
		return nil, errors.New("provide --file-id, or --finding")
	}
	return []FindingInputs{{Finding: opts.Finding, ClassHints: []string{opts.ClassHint}}}, nil
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

// fetchAppknoxInputs pulls every analysis + vulnerability (KnoxIQ) for the file
// and derives source-free finding/hint/remediation. Analyses without class hints
// or remediation are omitted.
func fetchAppknoxInputs(ctx context.Context, fileID int) ([]FindingInputs, error) {
	client := getClient()
	all, err := allAnalyses(ctx, client, fileID)
	if err != nil {
		return nil, err
	}
	var out []FindingInputs
	for _, a := range all {
		vuln, _, err := client.Vulnerabilities.GetByID(ctx, a.VulnerabilityID)
		if err != nil {
			return nil, err
		}
		in := deriveFindingInputs(a, vuln)
		if len(in.ClassHints) == 0 || in.Remediation == "" {
			continue
		}
		out = append(out, in)
	}
	return out, nil
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

// printDelivery renders the delivery outcome (dry-run or opened PR).
func printDelivery(opts AutofixOptions, out Outcome) {
	switch {
	case opts.DryRun:
		fmt.Printf("\n[dry-run] not pushing %d patched file(s).\n", len(out.Patches))
	case out.BranchURL != "":
		fmt.Printf("\nOpened PR for %d file(s): %s\n", len(out.Patches), out.BranchURL)
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
