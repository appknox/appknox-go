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
	"github.com/pmezard/go-difflib/difflib"
	"github.com/spf13/viper"
)

var (
	autofixPollInterval = 5 * time.Second
	autofixHardLimit    = time.Hour
	autofixSleep        = time.Sleep
)

// AutofixOptions carries the flags for the client-side autofix flow.
type AutofixOptions struct {
	Repo          string // GitHub owner/name from CI (GITHUB_REPOSITORY)
	Ref           string // PR base / merge target; empty = repo default branch
	HeadRef       string // feature branch this autofix belongs to (CI: GITHUB_HEAD_REF / GITHUB_REF)
	RepoPath      string // already-checked-out repo (CI: GITHUB_WORKSPACE)
	FileID        int    // Appknox file id (every fixable analysis on the file)
	AnalysisID    int    // one analysis on the file; 0 = every fixable analysis
	RiskThreshold int    // minimum computed risk to attempt; runAutofix defaults an unset (<=0) value to 1 -- see the comment there. 0 means "everything" only when passed to locatableAnalysisIDs directly, as every test and health-score mode do.
	Finding       string // manual finding detail (when not using file id)
	ClassHint     string // manual class/symbol hint
	GithubToken   string // GitHub token for the --repo fetch and branch push
	DryRun        bool   // locate + fix but do not push a branch
	FixMode       string // "agent" (the cmd/autofix.go flag default: client-side Edit, no upload) or "server" (/v1/fix, uploads the file)
	ListAnalyses  bool   // print the file's analyses + class hints, then exit

	// LocateOnly runs targeting and validation, prints each finding's
	// validated targets as TARGETS lines, and stops: no fix call, no job
	// registration, no delivery. Used to measure locate accuracy (spec 3.6).
	LocateOnly bool

	// Model overrides the model for BOTH turns. Empty keeps the agent layer's
	// default rather than naming one here, so the default stays in exactly one
	// place (agent.runnerParams).
	Model string

	// LocateModel overrides the LOCATE turn only, falling back to Model and
	// then the default. Deliberately one-directional: a cheap model here cannot
	// weaken the shipped patch, because the fix turn never reads this field.
	LocateModel string
}

// autofixDeps are the injectable collaborators (seams for cost-free tests).
type autofixDeps struct {
	locateTargets func(ctx context.Context, cfg agent.Config, req agent.TargetRequest) (agent.TargetReply, error)
	fetch         func(ctx context.Context, fileID, analysisID int) (FindingInputs, error)
	analysisIDs   func(ctx context.Context, fileID, riskThreshold int) ([]int, error)
	submit        func(ctx context.Context, cfg fixservice.Config, req fixservice.Request) (fixservice.Result, error)
	agentFix      func(ctx context.Context, cfg agent.Config, req agent.FixRequest) (agent.FixResult, error)
	deliver       func(ctx context.Context, opts AutofixOptions, patches []filePatch) (Delivery, error)
	report        func(ctx context.Context, opts AutofixOptions, d Delivery, patches []filePatch) error
	knoxiqReady   func(ctx context.Context, fileID int) error
}

// defaultDeps wires every real collaborator except fetch and analysisIDs,
// which runAutofix fills in via withKnoxIQFetchers so they can share one
// per-run analysis cache. Leaving them nil here (rather than pointing them at
// package-level funcs) is what lets withKnoxIQFetchers tell "caller supplied
// a stub" apart from "use the real thing".
func defaultDeps() autofixDeps {
	return autofixDeps{
		locateTargets: agent.LocateTargets,
		submit:        fixservice.SubmitAndAwait,
		agentFix:      agent.FixFile,
		deliver:       deliverBranch,
		report:        reportAutofixPR,
		knoxiqReady:   checkKnoxIQReady,
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
	// Formatting is cosmetic advice about the patch -- tabs in a space-indented
	// file, say. Reported on the run and never enforced: see formatting.go.
	Formatting string
}

// Outcome is the source-free result of a run — one or more fixed files.
type Outcome struct {
	Located   []string    // every located path
	Patches   []filePatch // per-file fixes that changed something
	BranchURL string      // GitHub PR URL after delivery
	CommitSHA string      // git commit SHA of the pushed branch
	Branch    string      // pushed branch name
	PRCreated bool        // true when GitHub opened a new PR this run

	// Truncated explains why the run stopped before attempting every target,
	// and is empty when it did not.
	//
	// The gateway budget is per SESSION and one run is one session, so a large
	// scan can exhaust it partway through. Discarding the fixes already
	// produced would waste every model call the run had already spent and
	// leave the developer with nothing to review, so the work already done is
	// kept and delivered, and this field labels the result as partial.
	Truncated string

	// Findings holds one outcome line per KnoxIQ finding attempted, plus one
	// per analysis KnoxIQ gave nothing to fix (spec 3.4).
	Findings []findingOutcome
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
	// --file-id registers the job and waits until Processing, then locates,
	// fixes, and opens the PR. Waiting for Processed here deadlocks: that
	// status is written only after this CLI records the PR.
	if opts.FileID > 0 && !opts.DryRun && !opts.LocateOnly {
		done, err := processAutofixWait(context.Background(), opts.FileID)
		if err != nil {
			PrintError(err)
			os.Exit(1)
		}
		if done {
			return
		}
	}
	out, err := runAutofix(context.Background(), opts, defaultDeps())
	nothingToFix, fail := autofixExit(err)
	if nothingToFix {
		// A clean scan, an app whose findings are all third-party, or one
		// KnoxIQ declined to remediate are all successful runs that happen to
		// produce no patch. Returning here, without touching the Mycroft job
		// any further, matches baseline c32941e: that build never called
		// runAutofix's now-removed equivalent with an error at all on a clean
		// fetch, so the job it had already moved to Processing (via
		// processAutofixWait above) was simply left there -- printJobResult
		// only ever ran when out.BranchURL was non-empty. See
		// final-fix-report.md (I1) for the baseline read that established
		// this.
		fmt.Printf("Nothing to fix: %v\n", err)
		return
	}
	if fail {
		printOutcomeLines(out.Findings)
		PrintError(err)
		os.Exit(1)
	}
	printOutcome(opts, out)
	if opts.FileID > 0 && !opts.DryRun && out.BranchURL != "" {
		printJobResult(opts.FileID, out)
	}
}

// autofixExit classifies the result of runAutofix for ProcessAutofix's exit
// decision, factored out of ProcessAutofix so the clean-scan/outage split is
// testable without os.Exit.
//
// ErrNothingFixable is a real, successful answer -- a clean scan, or one
// where KnoxIQ judged nothing worth fixing -- and must not read as a failure
// (nothingToFix true, fail false). Any other non-nil error is a genuine
// outage (an unreachable KnoxIQ, a rejected credential, a missing repo) and
// must exit 1 (fail true). A nil error is neither.
func autofixExit(err error) (nothingToFix, fail bool) {
	if errors.Is(err, ErrNothingFixable) {
		return true, false
	}
	return false, err != nil
}

func processAutofixWait(ctx context.Context, fileID int) (alreadyDone bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, autofixHardLimit)
	defer cancel()
	if err := checkKnoxIQReady(ctx, fileID); err != nil {
		if isAutofixTimeout(ctx, err) {
			return false, autofixTimeoutError(fileID)
		}
		return false, err
	}
	req, err := awaitAutofix(ctx, getClient(), fileID)
	if err != nil {
		return false, err
	}
	if req != nil && req.Status == appknox.AutofixStatusProcessed {
		printJobSummary(req.Status, req.PRURL, false, true)
		return true, nil
	}
	return false, nil
}

func awaitAutofix(ctx context.Context, client *appknox.Client, fileID int) (*appknox.AutofixRequest, error) {
	if client == nil {
		return nil, fmt.Errorf("autofix start failed: missing Appknox client")
	}
	started, _, err := client.KnoxIQ.StartAutofix(ctx, fileID)
	if err != nil {
		if isAutofixTimeout(ctx, err) {
			reportAutofixTimeout(client, fileID)
			return nil, autofixTimeoutError(fileID)
		}
		return nil, fmt.Errorf("autofix start failed: %w", err)
	}
	fmt.Println("\nAutofix status:")
	return pollAutofix(ctx, client, fileID, started)
}

func pollAutofix(ctx context.Context, client *appknox.Client, fileID int, current *appknox.AutofixRequest) (*appknox.AutofixRequest, error) {
	last := ""
	for {
		if current == nil {
			return nil, fmt.Errorf("autofix status missing for file %d", fileID)
		}
		if current.Status != last {
			fmt.Printf("  %s\n", current.Status)
			last = current.Status
		}
		switch current.Status {
		case appknox.AutofixStatusProcessing:
			return current, nil
		case appknox.AutofixStatusProcessed:
			return current, nil
		case appknox.AutofixStatusErrored:
			msg := current.ErrorMessage
			if msg == "" {
				msg = "autofix failed"
			}
			return nil, fmt.Errorf("autofix errored for file %d: %s", fileID, msg)
		case appknox.AutofixStatusTimedOut:
			return nil, autofixTimeoutError(fileID)
		}
		if err := ctx.Err(); err != nil {
			reportAutofixTimeout(client, fileID)
			return nil, autofixTimeoutError(fileID)
		}
		autofixSleep(autofixPollInterval)
		if err := ctx.Err(); err != nil {
			reportAutofixTimeout(client, fileID)
			return nil, autofixTimeoutError(fileID)
		}
		next, _, err := client.KnoxIQ.GetAutofixStatus(ctx, fileID)
		if err != nil {
			if isAutofixTimeout(ctx, err) {
				reportAutofixTimeout(client, fileID)
				return nil, autofixTimeoutError(fileID)
			}
			return nil, fmt.Errorf("autofix status check failed: %w", err)
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
	// An unset RiskThreshold defaults to 1 (any non-Passed finding), not 0
	// (everything). locatableAnalysisIDs keeps analyses whose ComputedRisk is
	// >= this threshold, and on a real file most analyses are Passed
	// (ComputedRisk 0): measured on mfva file 24 (2026-09-21), 108 analyses
	// total but only 24 with ComputedRisk > 0. Defaulting to 0 would ask
	// KnoxIQ about all 108 instead of ~24, and the gateway has a real
	// per-session call budget -- isGatewayBudgetExhausted exists because that
	// budget gets exhausted. (locatableAnalysisIDs's own doc comment, in
	// autofix_targets.go, cites a SEPARATE measurement on mfva file 358 from
	// 2026-09-04 that happens to share this same 108-analyses total -- same
	// app, same scanner, so that is expected and not a typo of this one.)
	// This lives here, not inside locatableAnalysisIDs, so that function keeps
	// treating 0 as "everything" for any caller that passes it a threshold
	// directly (as every existing test does, and as health-score mode will).
	// AutofixOptions.RiskThreshold has no way today to distinguish "the caller
	// left this unset" from "the caller explicitly asked for 0" -- both are
	// the field's zero value -- so this default only applies to the CLI's own
	// AutofixOptions before anything downstream sees it; a future
	// --risk-threshold flag that wants 0 to mean "everything" will need its
	// own explicit signal (e.g. a flag-was-set bool) rather than relying on
	// the zero value.
	if opts.RiskThreshold <= 0 {
		opts.RiskThreshold = 1
	}
	token := viper.GetString("access-token")
	if token == "" {
		return Outcome{}, errors.New("autofix needs an Appknox access token (--access-token or APPKNOX_ACCESS_TOKEN)")
	}
	d = withKnoxIQFetchers(d)
	targets, err := resolveTargets(ctx, opts, d)
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
	// Once per run, not once per finding: describeBuild walks the build files
	// and the answer is identical for every analysis in the repository.
	profile := describeBuild(root).String()
	work := newWorkingTree(root)
	// Unconditional, not dry-run-only: this restores the developer's checkout
	// to what it was found regardless of whether the run actually wrote
	// anything, on the theory that leaving no trace on disk is correct
	// hygiene and, in CI, the checkout is ephemeral anyway. It is safe only
	// because nothing downstream of work.apply reads the patched files back
	// off disk -- delivery and PR reporting both build their payloads from
	// out.Patches in memory, and this defer does not fire until run() (and
	// therefore delivery) has returned. Anything added later that needs the
	// patched content after the loop must take it from out.Patches, not from
	// the working tree, or it will read what this defer just erased.
	defer func() {
		// Printed, not swallowed: a failed restore leaves the developer's own
		// checkout patched with no on-screen sign of it, and that is worse
		// than the run failing outright. It must not fail the run itself --
		// the fix was already delivered (or reported) by the time this runs.
		if err := work.restore(); err != nil {
			fmt.Printf("autofix: failed to restore the working tree to its original state: %v\n", err)
		}
	}()
	return fixSession{opts: opts, d: d, root: root, host: host, token: token,
		targets: targets, profile: profile, work: work}.run(ctx)
}

// memoizedAnalysesFor wraps list in a per-call cache keyed by fileID, local to
// the returned closure -- not a package-level variable, so nothing leaks
// between runs or tests. This is the mechanism the fetch/analysisIDs
// signature change exists for: fetch is called once per analysis target (up
// to ~18 on a real scan) but AnalysesService has no GetByID, only ListByFile,
// so without this cache every one of those calls would re-list the whole
// file. Split out from withKnoxIQFetchers so the caching contract itself is
// testable without a real Appknox client.
func memoizedAnalysesFor(
	list func(ctx context.Context, fileID int) ([]*appknox.Analysis, error),
) func(context.Context, int) ([]*appknox.Analysis, error) {
	cache := map[int][]*appknox.Analysis{}
	return func(ctx context.Context, fileID int) ([]*appknox.Analysis, error) {
		if cached, ok := cache[fileID]; ok {
			return cached, nil
		}
		all, err := list(ctx, fileID)
		if err != nil {
			return nil, err
		}
		cache[fileID] = all
		return all, nil
	}
}

// withKnoxIQFetchers fills in the real KnoxIQ-backed implementation of
// whichever of fetch / analysisIDs the caller left nil, independently: a
// caller that stubs only one of the two fields still gets the real,
// network-calling implementation of the other -- it is not conditioned on
// whether BOTH are already set. Every existing test supplies both, so this
// is a no-op for the whole existing suite; a test that means to stub the run
// end to end must still set both fields itself.
//
// Both real closures share one memoizedAnalysesFor cache of each file's
// analyses, so a run considering N analyses lists the file once, not N times
// -- see memoizedAnalysesFor.
func withKnoxIQFetchers(d autofixDeps) autofixDeps {
	analysesFor := memoizedAnalysesFor(func(ctx context.Context, fileID int) ([]*appknox.Analysis, error) {
		return allAnalyses(ctx, getClient(), fileID)
	})
	if d.fetch == nil {
		d.fetch = func(ctx context.Context, fileID, analysisID int) (FindingInputs, error) {
			return fetchKnoxIQInputs(ctx, analysesFor, fileID, analysisID)
		}
	}
	if d.analysisIDs == nil {
		d.analysisIDs = func(ctx context.Context, fileID, riskThreshold int) ([]int, error) {
			return locatableAnalysisIDs(ctx, analysesFor, fileID, riskThreshold)
		}
	}
	return d
}

// fixSession carries the resolved context for locating + fixing every target
// on a file (or one manual --finding).
type fixSession struct {
	opts    AutofixOptions
	d       autofixDeps
	root    string
	host    string
	token   string
	targets []analysisTarget
	// profile describes the build system this checkout uses, handed to the
	// fixer up front because it cannot infer any of it from its one file.
	profile string
	// work is shared across analyses so two findings in the same file compose
	// instead of overwriting each other.
	work *workingTree
	// tally counts locate and fix calls for the all-failed exit decision.
	// run() sets it; a nil tally records nothing.
	tally *callTally
}

// run locates and fixes each finding, then delivers every patch on one branch.
//
// A locate or fix call that fails because the gateway's per-SESSION model-call
// budget is exhausted (isGatewayBudgetExhausted) is not an ordinary failure:
// every remaining target would fail the identical way, so the run stops
// attempting further targets rather than logging N identical failures, but it
// does NOT discard what was already produced -- see Outcome.Truncated. This is
// the guard the fetch loop in autofix_targets.go already has for the KnoxIQ
// GETs; this is the same guard for the two calls that actually go through the
// gateway (locate and fix).
//
// The unit of work is a KnoxIQ finding (spec 3.3): each analysis's findings
// (unitsOf) are located and fixed one at a time via runUnit, in manifest →
// res → source order within a finding, rather than the whole analysis
// sharing one locate call.
func (s fixSession) run(ctx context.Context) (Outcome, error) {
	s.tally = &callTally{}
	out := Outcome{}
	located := map[string]bool{}
targetLoop:
	for i, t := range s.targets {
		in := t.Inputs
		// Findings KnoxIQ gave us but that never became a Unit (F1): filtered
		// while a sibling stayed fixable, or left with no remediation text.
		// Each already carries its own outcome line.
		out.Findings = append(out.Findings, in.Skipped...)
		if in.Remediation == "" && in.SkipReason != "" {
			out.Findings = append(out.Findings, skippedAnalysis(t.AnalysisID, in))
			continue
		}
		units := unitsOf(in)
		for j, u := range units {
			res, err := s.runUnit(ctx, in, u)
			out = mergeUnit(out, located, res)
			if err == nil {
				continue
			}
			if isGatewayBudgetExhausted(err) {
				s.truncate(&out, i, err)
				// The unit that hit the exhaustion already has its own line
				// from runUnit above; everything after it -- its own
				// siblings, then every later target -- never got a call and
				// otherwise gets no line at all (F4).
				out.Findings = append(out.Findings, notAttemptedOutcomes(in, units[j+1:])...)
				out.Findings = append(out.Findings, remainingNotAttempted(s.targets[i+1:])...)
				break targetLoop
			}
			return out, err
		}
	}
	if s.tally.allFailed() {
		return out, fmt.Errorf("%w: %d of %d locate/fix calls failed, last: %v",
			ErrAllCallsFailed, s.tally.failures, s.tally.calls, s.tally.last)
	}
	// One file, one blob. Two analyses that patched the same file each appended
	// a patch; the last holds both fixes because each was built on the previous
	// one via the working tree. Shipping both would push the intermediate state.
	// lastPatchPerPath is handed s.work.original so it can recompute Finding
	// and Diff across the ORIGINAL content when it collapses more than one
	// patch on the same path -- see its own doc comment. s.work is nil in a
	// handful of narrow unit tests that never reach a patch (e.g.
	// TestRun_EmptyRemediationNeverReachesTheFixer); guard rather than
	// dereference, since a nil map read is safe and out.Patches is empty then
	// anyway.
	var original map[string]string
	if s.work != nil {
		original = s.work.original
	}
	out.Patches = lastPatchPerPath(out.Patches, original)
	if len(out.Patches) == 0 || s.opts.DryRun {
		return out, nil
	}
	return s.deliver(ctx, out)
}

// truncate records why the run is stopping before every target was attempted,
// and prints an unmissable warning. i is the index of the target being
// attempted when cause fired, so i targets were already fully attempted
// (successfully or not) before it.
//
// Exit-code decision: a truncated run that still delivers patches exits 0 --
// the work done is good, and this Truncated warning (surfaced again in
// printOutcome) is the signal that something was cut short, not a failure
// that should paint the CI run red. See final-fix-report.md (I3).
func (s fixSession) truncate(out *Outcome, i int, cause error) {
	out.Truncated = fmt.Sprintf(
		"KnoxIQ gateway budget exhausted after %d/%d target(s); the remaining %d were not attempted (%v). "+
			"Re-run to continue from here; the patch(es) already produced are still delivered.",
		i, len(s.targets), len(s.targets)-i, cause)
	fmt.Printf("\n!! %s\n", out.Truncated)
}

// maxFixRetries is how many times a rejected patch is regenerated before the
// file is abandoned. One retry: the gate tells the fixer the one fact it could
// not see, and a second miss on the same fact is not a third-attempt problem.
const maxFixRetries = 1

// produceFix generates a patch for one file and holds it to the static gate,
// retrying once with the violated fact before abandoning the file.
//
// The gate is relative, not absolute: verifyPatch compares the patch against
// the original, so a repository that already fails a check is never blamed on
// the patch that did not introduce it.
func (s fixSession) produceFix(ctx context.Context, path string, in FindingInputs) (fixservice.Result, error) {
	res, _, err := s.produceFixFor(ctx, path, in, targetContext{})
	return res, err
}

// produceFixFor is produceFix with the target's place in a multi-file
// remediation, and it says why no patch came back: reasonDeclined when the
// fixer abstained, "rejected by patch gate (<rule>)" when the gate discarded
// the patch after its retry.
func (s fixSession) produceFixFor(
	ctx context.Context, path string, in FindingInputs, tc targetContext,
) (fixservice.Result, string, error) {
	for attempt, violation := 0, ""; ; attempt++ {
		res, err := s.attemptFix(ctx, path, in, tc, violation)
		if err != nil {
			return res, "", err
		}
		// Nothing to check. An abstention is already the safe outcome -- the
		// gate exists to turn a bad edit into one of these.
		if !res.Changed || res.PatchedContent == "" {
			return res, reasonDeclined, nil
		}
		// The original is what is on disk: the fixer restores the file before
		// it returns, so the checkout still holds the pre-patch content. An
		// unreadable file means no delta can be computed, and a check that
		// cannot be computed must not reject.
		original, readErr := readUnderRoot(s.root, path)
		if readErr != nil {
			return res, "", nil
		}
		v := verifyPatch(s.root, path, original, res.PatchedContent)
		if v == nil {
			return res, "", nil
		}
		if attempt >= maxFixRetries {
			// Discard the patch rather than ship it. A reported gap is
			// recoverable; a branch that does not compile is not.
			fmt.Printf("   !! %s rejected (%s); no edit made\n", path, v.Rule)
			return fixservice.Result{}, fmt.Sprintf("rejected by patch gate (%s)", v.Rule), nil
		}
		fmt.Printf("   .. %s rejected (%s); retrying once\n", path, v.Rule)
		violation = v.Detail
	}
}

// attemptFix runs one fix turn, client-side via the agent's Edit tool
// (--fix-mode agent — NO upload), or server-side via /v1/fix (default).
// priorViolation is the fact the previous attempt got wrong, empty on the first.
// tc is the target's place in a multi-file remediation; server mode ignores it.
func (s fixSession) attemptFix(
	ctx context.Context, path string, in FindingInputs, tc targetContext, priorViolation string,
) (fixservice.Result, error) {
	if s.opts.FixMode == "agent" {
		// Model only, never LocateModel: this turn writes the patch that ships.
		fr, err := s.d.agentFix(ctx, agent.Config{Host: s.host, Token: s.token,
			Model: s.opts.Model},
			agent.FixRequest{RepoRoot: s.root, Path: path,
				Finding: in.Finding, Remediation: in.Remediation,
				// KnoxIQ's own developer-facing wording and its verification
				// criteria, so the fixer aims at them instead of only the
				// generic Remediation prose -- see agent/instructions.go's
				// fixUserPrompt, which renders both when present.
				DeveloperPrompt: in.DeveloperPrompt, Criteria: in.Criteria,
				ProjectProfile: s.profile, PriorViolation: priorViolation,
				Why: tc.Why, OtherFiles: tc.OtherFiles})
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
	out.PRCreated = del.PRCreated
	if s.d.report != nil {
		if err := s.d.report(ctx, s.opts, del, out.Patches); err != nil {
			return out, fmt.Errorf("pushed %s but failed to record on Appknox: %w", del.URL, err)
		}
	}
	return out, nil
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

// fetchKnoxIQInputs resolves one analysis into locate + fix inputs.
//
// The vulnerability record supplies only the human-readable name; the
// remediation itself is KnoxIQ's. An empty Remediation (nil error) means
// KnoxIQ was reached and judged nothing fixable here -- the caller drops the
// analysis. An error means KnoxIQ was UNREACHABLE, and the caller must not
// substitute metadata-derived guidance (deriveFindingInputs/remediationText).
//
// AnalysesService has no GetByID (see appknox/analyses.go), only ListByFile,
// so the analysis is looked up in whatever analysesFor returns -- the real
// caller (withKnoxIQFetchers) passes a memoized listing shared across every
// analysis target in the run.
func fetchKnoxIQInputs(
	ctx context.Context,
	analysesFor func(context.Context, int) ([]*appknox.Analysis, error),
	fileID, analysisID int,
) (FindingInputs, error) {
	all, err := analysesFor(ctx, fileID)
	if err != nil {
		return FindingInputs{}, err
	}
	analysis := findAnalysisByID(all, analysisID)
	if analysis == nil {
		return FindingInputs{}, fmt.Errorf("analysis %d not found on file %d", analysisID, fileID)
	}
	client := getClient()
	vuln, _, err := client.Vulnerabilities.GetByID(ctx, analysis.VulnerabilityID)
	if err != nil {
		return FindingInputs{}, err
	}
	findings, filteredSkips, skip, err := fixableKnoxIQFindings(ctx, client, analysisID, vuln.Name)
	if err != nil {
		return FindingInputs{}, err
	}
	if len(findings) == 0 {
		return FindingInputs{Finding: vuln.Name, VulnerabilityID: analysis.VulnerabilityID, SkipReason: skip}, nil
	}
	in := knoxIQInputs(findings, vuln.Name)
	in.VulnerabilityID = analysis.VulnerabilityID
	// Findings dropped before knoxIQInputs saw them (filtered while a sibling
	// stayed fixable) and findings knoxIQInputs itself dropped (no
	// remediation text) both land here, each with exactly one outcome line
	// (F1). VulnerabilityID is stamped now because neither producer knows it.
	in.Skipped = append(filteredSkips, in.Skipped...)
	for i := range in.Skipped {
		in.Skipped[i].VulnerabilityID = analysis.VulnerabilityID
	}
	return in, nil
}

// findAnalysisByID returns the analysis with the given id, or nil.
func findAnalysisByID(all []*appknox.Analysis, id int) *appknox.Analysis {
	for _, a := range all {
		if a.ID == id {
			return a
		}
	}
	return nil
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
	// Printed first: a partial run is the single most important thing to know
	// about the result, and it explains a finding count lower than the scan's.
	if out.Truncated != "" {
		fmt.Printf("PARTIAL RUN: %s\n", out.Truncated)
	}
	printOutcomeLines(out.Findings)
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
		if p.Formatting != "" {
			fmt.Printf("formatting (not enforced): %s\n", p.Formatting)
		}
		fmt.Println(p.Diff)
	}
	printDelivery(opts, out)
}

// printDelivery renders the delivery outcome (dry-run or created/updated PR).
func printDelivery(opts AutofixOptions, out Outcome) {
	switch {
	case opts.DryRun:
		fmt.Printf("\n[dry-run] not pushing %d patched file(s).\n", len(out.Patches))
	case out.BranchURL != "" && opts.FileID > 0:
		// ProcessAutofix prints Autofix request + Created/Updated PR after Mycroft records it.
		return
	case out.BranchURL != "":
		fmt.Printf("\n%s: %s\n", prAction(out.PRCreated), out.BranchURL)
		if out.CommitSHA != "" {
			fmt.Printf("commit: %s\n", out.CommitSHA)
		}
	default:
		fmt.Printf("\nGenerated fix for %d file(s): %s\n", len(out.Patches), patchPaths(out.Patches))
	}
}

func printJobResult(fileID int, out Outcome) {
	status := appknox.AutofixStatusProcessed
	prURL := out.BranchURL
	if client := getClient(); client != nil {
		req, _, err := client.KnoxIQ.GetAutofixStatus(context.Background(), fileID)
		if err == nil && req != nil {
			status = req.Status
			if req.PRURL != "" {
				prURL = req.PRURL
			}
		}
	}
	printJobSummary(status, prURL, out.PRCreated, false)
	if out.CommitSHA != "" {
		fmt.Printf("commit: %s\n", out.CommitSHA)
	}
}

// printJobSummary prints Mycroft job status and the GitHub PR.
// existing is true when this run did not create or update a PR (already Processed).
func printJobSummary(status, prURL string, created, existing bool) {
	fmt.Println()
	if status != "" {
		fmt.Printf("Autofix request: %s\n", status)
	}
	if prURL == "" {
		return
	}
	if existing {
		fmt.Printf("PR: %s\n", prURL)
		return
	}
	fmt.Printf("%s: %s\n", prAction(created), prURL)
}

func prAction(created bool) string {
	if created {
		return "Created PR"
	}
	return "Updated PR"
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

// lastPatchPerPath keeps one patch per path, preserving first-seen order so
// the pull request body still reads in the order fixes were made.
//
// The kept filePatch's Content is always the LAST patch's -- that is correct,
// since the final content already carries every earlier fix to that path via
// the working tree. But naively keeping the last patch's own Finding and Diff
// too would under-report every earlier finding that also touched the path:
// its Diff would cover only the last turn's edit, and its Finding would name
// only the last finding. So when MORE THAN ONE patch touches a path, this
// merges every patch's Finding name (deduplicated, first-seen order) and
// recomputes the Diff from the path's ORIGINAL content -- before this run
// touched it at all -- to the FINAL content, never from an intermediate
// state. A path with only one patch is untouched by this: its Finding and
// Diff already correctly describe that one patch.
//
// original is s.work.original -- the content read the first time each path
// was touched THIS run, i.e. before any of this run's own fixes.
func lastPatchPerPath(patches []filePatch, original map[string]string) []filePatch {
	latest := make(map[string]filePatch, len(patches))
	findingSeen := map[string]map[string]bool{}
	findingOrder := map[string][]string{}
	var order []string
	for _, p := range patches {
		if _, seen := latest[p.Path]; !seen {
			order = append(order, p.Path)
			findingSeen[p.Path] = map[string]bool{}
		}
		latest[p.Path] = p
		if p.Finding != "" && !findingSeen[p.Path][p.Finding] {
			findingSeen[p.Path][p.Finding] = true
			findingOrder[p.Path] = append(findingOrder[p.Path], p.Finding)
		}
	}
	out := make([]filePatch, 0, len(order))
	for _, path := range order {
		out = append(out, collapsedPatch(latest[path], findingOrder[path], original[path]))
	}
	return out
}

// collapsedPatch merges names (every distinct Finding seen for p.Path) and
// before (the path's original content, "" and absent are indistinguishable
// here, but an empty original is never a valid pre-patch state for a file
// that was actually touched) into p when more than one patch touched the
// path. A single-patch path is returned unchanged.
func collapsedPatch(p filePatch, names []string, before string) filePatch {
	if len(names) <= 1 {
		return p
	}
	p.Finding = strings.Join(names, "; ")
	if before != "" {
		if d := unifiedDiff(p.Path, before, p.Content); d != "" {
			p.Diff = d
		}
	}
	return p
}

// unifiedDiff renders a standard unified diff between two whole-file
// contents. Used only by collapsedPatch, where the diff must span the path's
// ORIGINAL content to its FINAL content rather than an intermediate state.
func unifiedDiff(path, before, after string) string {
	text, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(before), B: difflib.SplitLines(after),
		FromFile: path, ToFile: path, Context: 3,
	})
	if err != nil {
		return ""
	}
	return text
}
