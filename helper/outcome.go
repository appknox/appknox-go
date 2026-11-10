package helper

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/appknox/appknox-go/agent"
)

// Outcome lines (spec 3.4): one per KnoxIQ finding, and one per analysis
// KnoxIQ gave nothing fixable. FIXED means a patch was produced; only a rescan
// proves the finding cleared.

const (
	statusFixed   = "FIXED"
	statusPartial = "PARTIAL"
	statusSkipped = "SKIPPED"
	statusTargets = "TARGETS" // --locate-only: what would be fixed

	reasonDeclined = "declined: no edit made"

	// reasonNeedsNewFile is a whole finding's SKIPPED reason when its
	// remediation needs a file that does not exist in the repository yet.
	// New-file support is out of scope, and fixing the finding's other
	// targets would still leave a dangling reference, so the whole finding
	// is skipped instead of half-applied.
	reasonNeedsNewFile = "needs a new file (not supported)"

	// reasonThirdPartyNoSource is a third-party finding's SKIPPED reason when
	// no file in this repository carries its fix: the code to change is the
	// library's own, which the customer cannot patch.
	reasonThirdPartyNoSource = "third-party: no source in this repository to change"
)

// ErrAllCallsFailed marks a run in which every locate and fix call failed at
// the transport level, for example a gateway 404. Declined or skipped
// findings are real answers and never produce it.
var ErrAllCallsFailed = errors.New("every model call failed")

// targetResult is what happened to one target of one finding.
type targetResult struct {
	Path    string
	Patched bool
	Reason  string // why there is no patch; empty when Patched
	New     bool   // the target was a file this unit creates
}

// findingOutcome is one printed outcome line.
type findingOutcome struct {
	VulnerabilityID int
	Finding         string
	// Title is the KnoxIQ finding's own title (FindingUnit.Title), printed
	// after Finding so sibling findings of the same analysis -- which share
	// the same VulnerabilityID and Finding name -- can be told apart. Empty
	// on lines that are not about one specific KnoxIQ finding (an analysis-
	// level skip, or the manual --finding path).
	Title  string
	Status string
	Detail string
}

// summarizeFinding turns a finding's target results into its line. A
// not-found note never downgrades FIXED: those names are framework or library
// code, out of scope by product decision. A refused, declined or failed target
// does downgrade it, because part of the remediation was not applied.
func summarizeFinding(vulnID int, finding string, results []targetResult, notes []string) findingOutcome {
	o := findingOutcome{VulnerabilityID: vulnID, Finding: finding}
	var ok, failed []string
	for _, r := range results {
		if r.Patched {
			ok = append(ok, r.Path)
			continue
		}
		failed = append(failed, r.Path+" "+r.Reason)
	}
	switch {
	case len(ok) > 0 && len(failed) == 0:
		o.Status = statusFixed
		o.Detail = joinNonEmpty(append([]string{strings.Join(ok, ", ")}, notes...), "; ")
	case len(ok) > 0:
		o.Status = statusPartial
		o.Detail = joinNonEmpty(append([]string{strings.Join(ok, ", ") + " ok"}, append(failed, notes...)...), "; ")
	default:
		o.Status = statusSkipped
		o.Detail = firstNonEmpty(joinNonEmpty(append(failed, notes...), "; "), "locate: no targets")
	}
	return o
}

// locatedOutcome is the --locate-only line: the validated targets with their
// reasons, then what was refused and what was not found.
func locatedOutcome(in FindingInputs, accepted []agent.Target, results []targetResult, notes []string) findingOutcome {
	parts := make([]string, 0, len(accepted)+len(results)+len(notes))
	for _, t := range accepted {
		mark := ""
		if t.New {
			mark = " [new]"
		}
		parts = append(parts, fmt.Sprintf("%s%s (%s)", t.Path, mark, t.Why))
	}
	for _, r := range results {
		parts = append(parts, r.Path+" "+r.Reason)
	}
	parts = append(parts, notes...)
	return findingOutcome{VulnerabilityID: in.VulnerabilityID, Finding: in.Finding,
		Status: statusTargets, Detail: firstNonEmpty(joinNonEmpty(parts, "; "), "locate: no targets")}
}

// skippedAnalysis is the line for an analysis KnoxIQ gave nothing to fix.
func skippedAnalysis(analysisID int, in FindingInputs) findingOutcome {
	return findingOutcome{
		VulnerabilityID: in.VulnerabilityID,
		Finding:         firstNonEmpty(in.Finding, fmt.Sprintf("analysis %d", analysisID)),
		Status:          statusSkipped,
		Detail:          firstNonEmpty(in.SkipReason, "KnoxIQ: nothing fixable"),
	}
}

// reasonNotAttempted is F4's line for a unit the run stopped before ever
// reaching: the gateway budget ran out on an earlier unit, so nothing was
// actually asked about this one.
const reasonNotAttempted = "not attempted: gateway budget exhausted"

// notAttemptedOutcomes gives each unit in units its own SKIPPED line, for the
// siblings of a unit that hit gateway-budget exhaustion (spec 3.4 / F4): the
// run stops before calling locate or fix for them, so without this they get
// no line at all.
func notAttemptedOutcomes(in FindingInputs, units []FindingUnit) []findingOutcome {
	out := make([]findingOutcome, 0, len(units))
	for _, u := range units {
		out = append(out, findingOutcome{
			VulnerabilityID: in.VulnerabilityID, Finding: in.Finding, Title: u.Title,
			Status: statusSkipped, Detail: reasonNotAttempted,
		})
	}
	return out
}

// remainingNotAttempted covers every target the run never even started once
// it stopped for gateway-budget exhaustion (F4). A target already skipped by
// KnoxIQ (Skipped entries, or the whole analysis via SkipReason) keeps its
// real reason -- that was decided before any model call and does not depend
// on the budget -- and only a target that would actually have been attempted
// gets the not-attempted line.
func remainingNotAttempted(targets []analysisTarget) []findingOutcome {
	var out []findingOutcome
	for _, t := range targets {
		in := t.Inputs
		out = append(out, in.Skipped...)
		if in.Remediation == "" && in.SkipReason != "" {
			out = append(out, skippedAnalysis(t.AnalysisID, in))
			continue
		}
		out = append(out, notAttemptedOutcomes(in, unitsOf(in))...)
	}
	return out
}

// rejectionResults records validation refusals as unpatched targets.
func rejectionResults(rs []rejection) []targetResult {
	out := make([]targetResult, 0, len(rs))
	for _, r := range rs {
		out = append(out, targetResult{Path: r.Path, Reason: "rejected: " + r.Reason})
	}
	return out
}

// notFoundNotes renders the agent's not_found entries.
func notFoundNotes(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, "not found in repo: "+n)
	}
	return out
}

// notNewNotes renders needs_new_file entries the repo disproved -- the agent
// claimed a file was new but genuinelyNew found it already exists -- the same
// way notFoundNotes renders not_found entries, so the false claim stays
// visible on the outcome line even though it did not skip the finding.
func notNewNotes(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, "not new: "+needsNewFileName(e)+" already exists in repo")
	}
	return out
}

// formatOutcomeLine renders one line: status, vulnerability id, name, detail.
// The name is "<Finding> / <Title>" when a title is present, keeping the rest
// of the line format unchanged; with no title it is exactly what always
// printed.
func formatOutcomeLine(o findingOutcome) string {
	id := "-"
	if o.VulnerabilityID > 0 {
		id = strconv.Itoa(o.VulnerabilityID)
	}
	name := o.Finding
	if o.Title != "" {
		name = name + " / " + o.Title
	}
	return fmt.Sprintf("%-8s %-4s %-34s %s", o.Status, id, name, o.Detail)
}

// printOutcomeLines prints the run's outcome block.
func printOutcomeLines(findings []findingOutcome) {
	if len(findings) == 0 {
		return
	}
	fmt.Println("\nFindings:")
	for _, f := range findings {
		fmt.Println(formatOutcomeLine(f))
	}
}

// callTally counts locate and fix calls and their transport failures, for the
// exit-code decision. Gateway-budget errors are not counted: they truncate
// the run (Outcome.Truncated), which already exits 0 with the work done.
type callTally struct {
	calls    int
	failures int
	last     error
}

func (c *callTally) record(err error) {
	if c == nil || isGatewayBudgetExhausted(err) {
		return
	}
	c.calls++
	if err != nil && !errors.Is(err, agent.ErrUnparseableReply) {
		c.failures++
		c.last = err
	}
}

func (c *callTally) allFailed() bool {
	return c != nil && c.calls > 0 && c.failures == c.calls
}
