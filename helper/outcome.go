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
		parts = append(parts, fmt.Sprintf("%s (%s)", t.Path, t.Why))
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
		out = append(out, "not found in repo: "+n+" (likely third-party)")
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
