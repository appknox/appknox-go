package helper

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// isGatewayBudgetExhausted reports whether err is the gateway refusing further
// model calls for this session, rather than a fault in the fix itself.
//
// Matched on response text because the SDK surfaces the gateway's body as an
// opaque error with no typed status to switch on. Both forms below are the same
// event from the caller's point of view -- this session is finished, and the
// work already done is still good:
//
//	429 {"detail":"session call budget exhausted"}  maxCallsPerSession spent
//	403 {"detail":"invalid credential"}             session expired, or the
//	                                                gateway restarted and lost
//	                                                its in-memory session store
//
// Deliberately narrow: a looser match would swallow real fix failures and
// report a truncated run where there was actually a bug.
func isGatewayBudgetExhausted(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "session call budget exhausted") ||
		strings.Contains(msg, "invalid credential")
}

// A run covers a WHOLE FILE by default, not one finding.
//
// Asking a developer which analysis id to fix is asking them to redo the triage
// the scanner already did. Given just --file-id, every locatable analysis is
// attempted and the results land in ONE pull request -- one branch per scan
// rather than one per finding, which is the difference between a review and an
// inbox.

// ErrNothingFixable marks a run that reached everything it needed and found
// nothing to fix. That is a real answer, not a failure.
//
// The distinction is load-bearing at corpus scale. Across many repositories most
// runs legitimately have nothing to remediate: the app is clean, every finding is
// third-party, or KnoxIQ judged none of them worth a patch. Exiting non-zero
// there paints healthy repositories red and teaches everyone to ignore the
// signal -- which then hides the runs that failed for real reasons, an
// unreachable KnoxIQ or a bad credential among them.
//
// Callers separate the two with errors.Is rather than by matching message text,
// so the wording below stays free to change.
var ErrNothingFixable = errors.New("nothing to fix")

// analysisTarget is one analysis to attempt, with its resolved inputs.
type analysisTarget struct {
	AnalysisID int
	Inputs     FindingInputs
}

// analysisReport records what happened for one analysis, delivered or not.
type analysisReport struct {
	AnalysisID int
	Finding    string
	Located    []string
	Patches    int
	// Unfixed are files THIS analysis located that produced no patch.
	//
	// Recorded per analysis rather than derived afterwards from the run's whole
	// patch set: two analyses often locate the same file, so a file patched for
	// one would look patched for the other. Not hypothetical -- on file 348 the
	// Weak PRNG analysis patched MainActivity.java while the Derived Crypto Keys
	// analysis located that same file and left its hardcoded DES key alone.
	Unfixed []string
	// Remediation and DeveloperPrompt are what KnoxIQ asked for, kept so the run
	// can echo the instruction beside the patch it produced. A diff is only
	// judgeable against the instruction behind it, and the run used to report
	// the patch and the verdict while never recording what was requested.
	Remediation     string
	DeveloperPrompt string
	Verification    VerificationReport
	Skipped         string // why nothing from this analysis was delivered
}

// resolveTargets decides what this run will attempt.
//
//   - --file-id with --analysis-id: just that one.
//   - --file-id alone: every analysis naming a first-party class. That filter is
//     local and free; without it we would ask KnoxIQ about scores of analyses
//     that could never be located anyway.
//   - --finding: the manual escape hatch, no Appknox lookup at all.
func resolveTargets(ctx context.Context, opts AutofixOptions, d autofixDeps) ([]analysisTarget, error) {
	if opts.FileID > 0 && opts.AnalysisID > 0 {
		inputs, err := d.fetch(ctx, opts.FileID, opts.AnalysisID)
		if err != nil {
			return nil, err
		}
		return []analysisTarget{{AnalysisID: opts.AnalysisID, Inputs: inputs}}, nil
	}
	if opts.FileID > 0 {
		return everyLocatableAnalysis(ctx, opts, d)
	}
	if opts.Finding == "" {
		return nil, errors.New(
			"provide --file-id (fixes every finding), --file-id + --analysis-id (one), or --finding")
	}
	return []analysisTarget{{
		Inputs: FindingInputs{Finding: opts.Finding, ClassHints: []string{opts.ClassHint}},
	}}, nil
}

// everyLocatableAnalysis resolves inputs for each candidate analysis on a file.
//
// One analysis failing does not abandon the rest: a single unreachable or
// malformed finding should not cost the developer every other fix in the scan.
// Those are reported and the run continues.
func everyLocatableAnalysis(
	ctx context.Context, opts AutofixOptions, d autofixDeps,
) ([]analysisTarget, error) {
	ids, err := d.analysisIDs(ctx, opts.FileID, opts.RiskThreshold)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf(
			"no analysis on file %d meets the risk threshold: %w",
			opts.FileID, ErrNothingFixable)
	}
	fmt.Printf("Considering %d analyses on file %d\n", len(ids), opts.FileID)

	targets := make([]analysisTarget, 0, len(ids))
	for _, id := range ids {
		inputs, err := d.fetch(ctx, opts.FileID, id)
		if err != nil {
			fmt.Printf("  analysis %d: skipped (%v)\n", id, err)
			continue
		}
		if inputs.Remediation == "" {
			continue // KnoxIQ judged nothing here worth fixing
		}
		targets = append(targets, analysisTarget{AnalysisID: id, Inputs: inputs})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("KnoxIQ has nothing fixable on file %d: %w",
			opts.FileID, ErrNothingFixable)
	}
	fmt.Printf("%d analysis(es) have a fix to attempt\n", len(targets))
	return targets, nil
}

// locatableAnalysisIDs returns the analyses on a file worth attempting.
//
// ONE filter: computed risk must meet the configured threshold. Autofix reuses
// the severity policy the customer already sets on cicheck rather than
// introducing a second one just for remediation -- nobody should have to
// configure "which vulnerabilities matter" twice. A threshold of 0 (Passed)
// means everything, which is what health-score mode wants.
//
// It used to ALSO require the finding to name a first-party class descriptor,
// on the reasoning that without one there is nothing to locate. That reasoning
// was wrong, and expensively so: on mfva file 358, 108 analyses produced 2
// candidates, and the 106 dropped included Critical and High findings. They
// were not minor -- they were manifest, network-config and framework issues
// whose finding text names no Lcom/...; class, so they were discarded before
// KnoxIQ was even asked whether they were fixable.
//
// The locate agent has read_file, grep and glob over the checkout and can find
// AndroidManifest.xml from a finding description perfectly well. A class hint
// is a useful seed, not a precondition, so the decision about what is fixable
// now belongs to KnoxIQ and the locate agent rather than to a regex here.
func locatableAnalysisIDs(ctx context.Context, fileID, riskThreshold int) ([]int, error) {
	all, err := allAnalyses(ctx, getClient(), fileID)
	if err != nil {
		return nil, err
	}
	var ids []int
	for _, a := range all {
		if int(a.ComputedRisk) < riskThreshold {
			continue
		}
		ids = append(ids, a.ID)
	}
	return ids, nil
}
