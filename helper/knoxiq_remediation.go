package helper

import (
	"context"
	"strings"

	"github.com/appknox/appknox-go/appknox"
)

// IsFixable reports whether a KnoxIQ finding is worth attempting a fix for.
//
// KnoxIQ has already judged what is real and whose code it is, so this reuses
// that verdict rather than re-deriving it. Per the KnoxIQ team, the API returns
// only TRUE_POSITIVE and UNCERTAIN findings; false positives are filtered
// server-side and never reach us.
//
// UNCERTAIN findings are therefore IN SCOPE by design -- they are sent
// deliberately, and the fix lands in a draft PR a human reviews.
//
// Validation absent is skipped. KnoxIQ records one for every finding it
// returns, so a missing validation means something went wrong upstream. We
// cannot establish the finding is real, so we do not touch the code. Treating
// this as fixable would mean editing on the strength of a failure.
//
// Third-party findings are NOT skipped here. is_third_party says the flagged
// code is a library, not where the fix goes: for mfva 37 (jedis) every step
// KnoxIQ gives edits the app's own files -- the dependency line in
// app/build.gradle and the Jedis usage in ExportedActivity.java. The locate
// agent is told the finding is third-party (FindingUnit.ThirdParty) and may
// target only files in this repository; validateTargets refuses vendored and
// generated paths; and a third-party finding with nothing left to change is
// skipped in runUnit as reasonThirdPartyNoSource.
//
// A nil IsValid inside a present validation still means "not recorded" rather
// than false: Go's zero value would otherwise silently mark such findings
// unfixable.
func IsFixable(f *appknox.KnoxIQFinding) bool {
	if f == nil || f.Validation == nil {
		return false
	}
	v := f.Validation
	if v.IsValid != nil && !*v.IsValid {
		return false
	}
	// Defence in depth: the API is not supposed to send these at all.
	return v.Verdict != "FALSE_POSITIVE"
}

// isThirdParty reports whether KnoxIQ marked the finding's code as a library.
// nil means not recorded, and not recorded is not third-party.
func isThirdParty(f *appknox.KnoxIQFinding) bool {
	return f != nil && f.Validation != nil && f.Validation.IsThirdParty != nil && *f.Validation.IsThirdParty
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
//
// A finding filtered out here while a SIBLING finding of the same analysis
// stays fixable (F1) used to vanish with no outcome line at all -- only the
// ALL-dropped case (below) ever built a reason. Each such finding now gets
// its own SKIPPED line in skipped, named by its own title.
//
// The string return is why NOTHING was kept, for the analysis-level outcome
// line; empty otherwise.
func fixableKnoxIQFindings(
	ctx context.Context, client *appknox.Client, analysisID int, vulnerabilityName string,
) (keep []*appknox.KnoxIQFinding, skipped []findingOutcome, allSkipReason string, err error) {
	findings, err := client.KnoxIQ.ListByAnalysis(ctx, analysisID)
	if err != nil {
		return nil, nil, "", err
	}
	keep = make([]*appknox.KnoxIQFinding, 0, len(findings))
	var dropped []*appknox.KnoxIQFinding
	for _, f := range findings {
		if IsFixable(f) {
			keep = append(keep, f)
		} else {
			dropped = append(dropped, f)
		}
	}
	if len(keep) == 0 {
		return keep, nil, unfixableReason(findings), nil
	}
	for _, f := range dropped {
		skipped = append(skipped, findingOutcome{
			Finding: vulnerabilityName, Title: f.Title, Status: statusSkipped,
			Detail: unfixableReason([]*appknox.KnoxIQFinding{f}),
		})
	}
	return keep, skipped, "", nil
}

// knoxIQInputs turns the fixable findings into the locate + fix inputs.
//
// ClassHints are for --list-analyses display only. Targeting uses Units, whose
// full text goes to the locate agent.
//
// Criteria come from remediation.verification and NOTHING ELSE. remediation.steps
// often names the same symbols and would usually work, but steps are
// instructions ("replace X with Y") while verification is an assertion ("confirm
// X is gone"). Checking a patch against instructions passes by coincidence of
// wording, and a gate that is right by accident is not a gate.
//
// Empty Criteria therefore means "could not check", never "nothing to check".
// But nothing in this branch enforces that distinction: there is no
// verification gate here. Criteria only reaches the fixer as guidance folded
// into the fix prompt (see attemptFix in autofix.go and fixUserPrompt in
// agent/instructions.go), and a patch ships whether or not any Criteria were
// present, let alone met.
//
// A finding whose FixInstruction is empty (F1) does not become a Unit -- a fix
// built on no instruction is worse than no fix -- but it still gets its own
// SKIPPED outcome line in FindingInputs.Skipped, rather than vanishing.
func knoxIQInputs(findings []*appknox.KnoxIQFinding, vulnerabilityName string) FindingInputs {
	var instructions, criteria, developerPrompts []string
	var units []FindingUnit
	var skipped []findingOutcome
	seenHint := map[string]bool{}
	var hints []string

	for _, f := range findings {
		text := FixInstruction(f)
		if text != "" {
			instructions = append(instructions, text)
			units = append(units, FindingUnit{
				Title: f.Title, Description: f.Description, Remediation: text,
				DeveloperPrompt: f.DeveloperPrompt, Criteria: verificationOf(f),
				ThirdParty: isThirdParty(f),
			})
		} else {
			skipped = append(skipped, findingOutcome{
				Finding: vulnerabilityName, Title: f.Title,
				Status: statusSkipped, Detail: "KnoxIQ: no remediation text",
			})
		}
		if f.Remediation != nil {
			criteria = append(criteria, f.Remediation.Verification...)
		}
		if strings.TrimSpace(f.DeveloperPrompt) != "" {
			developerPrompts = append(developerPrompts, f.DeveloperPrompt)
		}
		for _, hint := range classHintsFromFindings(f.Title + " " + f.Description) {
			if !seenHint[hint] {
				seenHint[hint] = true
				hints = append(hints, hint)
			}
		}
	}

	return FindingInputs{
		Finding:         vulnerabilityName,
		ClassHints:      hints,
		Remediation:     joinNonEmpty(instructions, "\n\n"),
		Criteria:        criteria,
		DeveloperPrompt: joinNonEmpty(developerPrompts, "\n\n"),
		Units:           units,
		Skipped:         skipped,
	}
}

// verificationOf returns the finding's verification assertions, or nil.
func verificationOf(f *appknox.KnoxIQFinding) []string {
	if f.Remediation == nil {
		return nil
	}
	return f.Remediation.Verification
}
