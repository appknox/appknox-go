package helper

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/appknox/appknox-go/appknox"
)

// Outcome lines: one per KnoxIQ finding. Appknox decides each finding's status
// from the results this CLI reports; FIXED means a patch was produced, and
// only a rescan proves the finding cleared.

const (
	statusSkipped = "SKIPPED"

	// reasonNeedsNewFile is a whole finding's SKIPPED reason when its
	// remediation needs a file whose place in the repository cannot be
	// determined. Fixing the other targets would leave a dangling reference.
	reasonNeedsNewFile = "needs a new file (not supported)"

	// reasonThirdPartyNoSource is a third-party finding's SKIPPED reason when
	// no file in this repository carries its fix: the code to change is the
	// library's own, which the customer cannot patch.
	reasonThirdPartyNoSource = "third-party: no source in this repository to change"

	// reasonRolledBack replaces a patched target's result when its unit was
	// rolled back: the remediation lands whole or not at all.
	reasonRolledBack = "rolled back: this remediation lands whole or not at all"
)

// targetResult is what happened to one target of one finding. It is the
// wire shape of AutofixTargetOutcome.
type targetResult struct {
	Path    string `json:"path"`
	Patched bool   `json:"patched"`
	Reason  string `json:"reason"` // why there is no patch; empty when Patched
	New     bool   `json:"new"`    // the target was a file this unit creates
}

// rejectionResults records validation refusals as unpatched targets.
func rejectionResults(rs []rejection) []targetResult {
	out := make([]targetResult, 0, len(rs))
	for _, r := range rs {
		out = append(out, targetResult{Path: r.Path, Reason: "rejected: " + r.Reason})
	}
	return out
}

// notFoundNotes renders the locate turn's not_found entries.
func notFoundNotes(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, "not found in repo: "+n)
	}
	return out
}

// notNewNotes renders needs_new_file entries the repo disproved -- claimed
// new, but genuinelyNew found the file -- so the false claim stays visible on
// the outcome line even though it did not skip the finding.
func notNewNotes(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, "not new: "+needsNewFileName(e)+" already exists in repo")
	}
	return out
}

// unpatchedDetail joins the refused targets and notes of a skipped finding.
func unpatchedDetail(results []targetResult, notes []string) string {
	parts := make([]string, 0, len(results)+len(notes))
	for _, r := range results {
		if !r.Patched {
			parts = append(parts, r.Path+" "+r.Reason)
		}
	}
	return joinNonEmpty(append(parts, notes...), "; ")
}

// joinNonEmpty joins only the parts that carry text.
func joinNonEmpty(parts []string, sep string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, sep)
}

// formatOutcomeLine renders one line: status, vulnerability id, name, detail.
// The name is "<Finding> / <Title>" when a title is present, so sibling
// findings of one analysis can be told apart.
func formatOutcomeLine(o appknox.AutofixOutcome) string {
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
func printOutcomeLines(findings []appknox.AutofixOutcome) {
	if len(findings) == 0 {
		return
	}
	fmt.Println("\nFindings:")
	for _, f := range findings {
		fmt.Println(formatOutcomeLine(f))
	}
}
