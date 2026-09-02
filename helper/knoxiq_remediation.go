package helper

import (
	"context"
	"strings"

	"github.com/appknox/appknox-go/appknox"
)

// IsFixable reports whether a KnoxIQ finding is worth attempting a fix for.
//
// KnoxIQ has already judged what is real and whose code it is, so this reuses
// that verdict instead of re-deriving it. Two cases are skipped:
//
//   - a FALSE_POSITIVE, or one KnoxIQ marked invalid -- there is nothing to fix
//   - code that is NOT first-party -- a vendored library cannot be patched in
//     the customer's tree, and attempting it is how autofix ends up rewriting
//     the wrong file
//
// Absent signals mean "not recorded", never "no". A nil Validation falls through
// to the normal gates, and a nil IsValid/IsThirdParty is not treated as false --
// relying on Go's zero value here would silently mark such findings unfixable.
func IsFixable(f *appknox.KnoxIQFinding) bool {
	if f == nil {
		return false
	}
	v := f.Validation
	if v == nil {
		return true
	}
	if v.IsValid != nil && !*v.IsValid {
		return false
	}
	if v.Verdict == "FALSE_POSITIVE" {
		return false
	}
	return v.IsThirdParty == nil || !*v.IsThirdParty
}

// FixInstruction assembles KnoxIQ's remediation into the guidance handed to the
// fixer, using KnoxIQ's own wording verbatim so the fix content stays theirs.
//
// Sections that are empty are omitted rather than emitted as bare headings.
func FixInstruction(f *appknox.KnoxIQFinding) string {
	if f == nil {
		return ""
	}
	if f.Remediation == nil {
		if f.Description != "" {
			return f.Description
		}
		return f.Title
	}
	rem := f.Remediation

	parts := []string{rem.Remediation}
	if len(rem.Steps) > 0 {
		parts = append(parts, "Steps:\n"+bulletList(rem.Steps))
	}
	if len(rem.CodeExamples) > 0 {
		parts = append(parts, "Reference fix:\n"+strings.Join(rem.CodeExamples, "\n\n"))
	}
	return joinNonEmpty(parts, "\n\n")
}

// bulletList renders items as "- item" lines.
func bulletList(items []string) string {
	lines := make([]string, 0, len(items))
	for _, item := range items {
		lines = append(lines, "- "+item)
	}
	return strings.Join(lines, "\n")
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

// fixableKnoxIQFindings fetches the findings for an analysis and keeps the ones
// worth attempting.
//
// The two failure modes are deliberately distinct, and callers must not collapse
// them:
//
//   - a non-nil error means KnoxIQ was UNREACHABLE (after retries). Fail. Do not
//     fall back to metadata-derived remediation -- a fix built on guessed
//     guidance is worse than no fix.
//   - an empty slice with a nil error means KnoxIQ was reached and judged
//     nothing fixable. Abstain cleanly; this is a real answer, not a failure.
//
// Collapsing these is what once let a 401 look like "nothing to fix" and
// silently skip a live vulnerability.
func fixableKnoxIQFindings(
	ctx context.Context, client *appknox.Client, analysisID int,
) ([]*appknox.KnoxIQFinding, error) {
	findings, err := client.KnoxIQ.ListByAnalysis(ctx, analysisID)
	if err != nil {
		return nil, err
	}
	keep := make([]*appknox.KnoxIQFinding, 0, len(findings))
	for _, f := range findings {
		if IsFixable(f) {
			keep = append(keep, f)
		}
	}
	return keep, nil
}

// knoxIQInputs turns the fixable findings into the locate + fix inputs.
//
// Criteria come from remediation.verification and NOTHING ELSE. remediation.steps
// often names the same symbols and would usually work, but steps are
// instructions ("replace X with Y") while verification is an assertion ("confirm
// X is gone"). Checking a patch against instructions passes by coincidence of
// wording, and a gate that is right by accident is not a gate.
//
// Empty Criteria therefore means "could not check", never "nothing to check",
// and the run says so rather than delivering an unverified patch.
func knoxIQInputs(findings []*appknox.KnoxIQFinding, vulnerabilityName string) FindingInputs {
	var instructions, criteria []string
	seenHint := map[string]bool{}
	var hints []string

	for _, f := range findings {
		if text := FixInstruction(f); text != "" {
			instructions = append(instructions, text)
		}
		if f.Remediation != nil {
			criteria = append(criteria, f.Remediation.Verification...)
		}
		for _, hint := range classHintsFromFindings(f.Title + " " + f.Description) {
			if !seenHint[hint] {
				seenHint[hint] = true
				hints = append(hints, hint)
			}
		}
	}

	return FindingInputs{
		Finding:     vulnerabilityName,
		ClassHints:  hints,
		Remediation: joinNonEmpty(instructions, "\n\n"),
		Criteria:    criteria,
	}
}
