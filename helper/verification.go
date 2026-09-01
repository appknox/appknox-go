package helper

import (
	"fmt"
	"regexp"
	"strings"
)

// Machine-check a produced fix against KnoxIQ's own verification criteria.
//
// remediation.verification is free-form prose written for a human, e.g.
// "Confirm that all Math.random() calls have been replaced with
// SecureRandom.nextInt()". Some of it is mechanically checkable and some is not
// ("Rebuild and test the onClick handler"). This extracts the checkable part and
// evaluates it against the patch, so the gate reports WHICH criteria were
// actually verified instead of asserting a blanket pass.
//
// The rule that makes extraction safe: a symbol is only treated as a REMOVAL
// TARGET when the patch actually deleted a line containing it. That keeps
// location hints (MainActivity$3) and prose nouns from being mistaken for tokens
// that must disappear. Anything ambiguous is not_checkable rather than guessed --
// a wrong "satisfied" is far more damaging than an honest "unchecked".
//
// Nothing here calls an LLM: it is deterministic, free, and cannot hallucinate.
// The stronger oracle is re-running the Appknox scan on the rebuilt artifact.

// CriterionStatus is the outcome of machine-checking one criterion.
type CriterionStatus string

const (
	// CriterionSatisfied means the patch demonstrably meets the criterion.
	CriterionSatisfied CriterionStatus = "satisfied"
	// CriterionViolated means the patch demonstrably fails it.
	CriterionViolated CriterionStatus = "violated"
	// CriterionNotCheckable means it cannot be decided from the patch alone.
	// This is NOT a pass.
	CriterionNotCheckable CriterionStatus = "not_checkable"
)

// symbolPatterns match code symbols named inside a criterion.
//
// KnoxIQ's live verification steps do NOT back-quote them ("all imports of
// java.util.Random and Math.random()"), while its remediation prose does -- so
// match both, and require a code SHAPE (a call, or a qualified or CamelCase
// name) so ordinary prose is never mistaken for an identifier.
var symbolPatterns = []*regexp.Regexp{
	regexp.MustCompile("`([^`\n]{2,80})`"),                            // `Math.random()`
	regexp.MustCompile(`\b((?:[A-Za-z_]\w*\.){1,6}[A-Za-z_]\w*\(\))`), // Math.random()
	regexp.MustCompile(`\b((?:[a-z]\w*\.){1,5}[A-Z]\w+)\b`),           // java.util.Random
	regexp.MustCompile(`\b([A-Za-z_]\w*\(\))`),                        // nextBytes()
	regexp.MustCompile(`\b([A-Z][a-z]+(?:[A-Z]\w+)+)\b`),              // SecureRandom
}

// removalCues are cue WORDS, not fixed phrases. KnoxIQ's wording varies per
// generation -- "no longer present", "no longer imported", "no other uses of",
// "should be removed or replaced" are all the same assertion -- so matching
// whole phrases is whack-a-mole. Keywords generalise; the removed-lines guard in
// checkRemoval is what keeps the looser match safe.
var removalCues = []string{
	"no longer", "no other use", "not present", "does not appear", "absent",
	"removed", "remove ", "replaced", "replace ", "eliminated",
}

// presenceCues stay STRICT and phrase-shaped on purpose. A removal check is
// guarded -- the symbol must appear in the patch's deleted lines -- but a
// presence check has no such guard, so a loose keyword ("uses", "call") will
// happily match a criterion that is really asserting ABSENCE and report a
// surviving insecure call as "satisfied". Correctness beats coverage here.
var presenceCues = []string{
	"is imported", "is instantiated", "are instantiated", "now instantiate",
	"is used", "is now used", "now uses", "is present", "is implemented",
	"confirm the use of", "has been replaced with", "replaced by", "replaced with",
}

// CriterionResult is the outcome of machine-checking one KnoxIQ criterion.
type CriterionResult struct {
	Criterion string          // the KnoxIQ criterion, verbatim
	Status    CriterionStatus // satisfied | violated | not_checkable
	Detail    string          // why -- names the symbol that decided it
}

// VerificationReport is the machine-checkable subset of KnoxIQ's criteria,
// evaluated against the patch.
type VerificationReport struct {
	Results []CriterionResult
}

// Violated returns the criteria the patch demonstrably fails.
func (r VerificationReport) Violated() []CriterionResult {
	return r.withStatus(CriterionViolated)
}

// Satisfied returns the criteria the patch demonstrably meets.
func (r VerificationReport) Satisfied() []CriterionResult {
	return r.withStatus(CriterionSatisfied)
}

func (r VerificationReport) withStatus(status CriterionStatus) []CriterionResult {
	var out []CriterionResult
	for _, res := range r.Results {
		if res.Status == status {
			out = append(out, res)
		}
	}
	return out
}

// Checked reports how many criteria could actually be decided.
func (r VerificationReport) Checked() int {
	return len(r.Satisfied()) + len(r.Violated())
}

// Summary renders a one-line human summary.
func (r VerificationReport) Summary() string {
	return fmt.Sprintf("%d/%d criteria machine-checked, %d satisfied, %d violated",
		r.Checked(), len(r.Results), len(r.Satisfied()), len(r.Violated()))
}

// checkCriteria evaluates KnoxIQ's verification criteria against the patches.
//
// Criteria that cannot be decided from the patch alone come back as
// not_checkable -- they are NOT counted as passes.
func checkCriteria(patches []filePatch, criteria []string) VerificationReport {
	removed := removedText(patches)
	patched := patchedText(patches)

	var report VerificationReport
	for _, criterion := range criteria {
		if strings.TrimSpace(criterion) == "" {
			continue
		}
		report.Results = append(report.Results, checkOne(criterion, removed, patched))
	}
	return report
}

// VerificationGate decides whether a patch may be delivered.
//
// It fails closed in three distinct ways, and the distinction matters because
// each has a different fix:
//
//   - no criteria at all -- KnoxIQ recorded none for this finding (typically an
//     analysis stored before the storage layer stopped discarding them). We
//     cannot check the patch, so we do not certify it. Re-run the analysis.
//   - a violated criterion -- the patch demonstrably fails KnoxIQ's own test.
//     This is the case the gate exists for.
//   - criteria present but none decidable -- every step was manual or named no
//     code symbol. Undecidable is not a pass.
//
// "Could not check" must never be reported as success; that is exactly how a
// broken patch would reach a customer's branch.
func VerificationGate(report VerificationReport, criteriaCount int) error {
	if criteriaCount == 0 {
		return fmt.Errorf(
			"refusing to deliver: KnoxIQ supplied no verification criteria for this " +
				"finding, so the patch cannot be checked (re-run the analysis to " +
				"populate remediation.verification)")
	}
	if violated := report.Violated(); len(violated) > 0 {
		return fmt.Errorf("refusing to deliver: %s — %s",
			report.Summary(), violated[0].Detail)
	}
	if report.Checked() == 0 {
		return fmt.Errorf(
			"refusing to deliver: %s — none of KnoxIQ's criteria could be "+
				"machine-checked against this patch", report.Summary())
	}
	return nil
}

// checkOne evaluates a single criterion, preferring not_checkable to a guess.
func checkOne(criterion, removed, patched string) CriterionResult {
	symbols := namedSymbols(criterion)
	if len(symbols) == 0 {
		return CriterionResult{criterion, CriterionNotCheckable,
			"no code symbol named (runtime, manual, or process step)"}
	}
	var result CriterionResult
	switch {
	case hasCue(criterion, removalCues):
		result = checkRemoval(symbols, removed, patched)
	case hasCue(criterion, presenceCues):
		result = checkPresence(symbols, patched)
	default:
		return CriterionResult{criterion, CriterionNotCheckable,
			"no removal/presence assertion recognised in the wording"}
	}
	result.Criterion = criterion
	return result
}

// checkRemoval asserts each symbol the patch deleted no longer survives.
//
// Only symbols that actually appear in the deleted lines are treated as removal
// targets; location hints and prose nouns are ignored rather than guessed at.
// This guard is what makes the loose removal cues safe.
func checkRemoval(symbols []string, removed, patched string) CriterionResult {
	var targets []string
	for _, s := range symbols {
		if strings.Contains(removed, s) {
			targets = append(targets, s)
		}
	}
	if len(targets) == 0 {
		return CriterionResult{Status: CriterionNotCheckable,
			Detail: "no named symbol was removed by this patch"}
	}
	var survivors []string
	for _, s := range targets {
		if strings.Contains(patched, s) {
			survivors = append(survivors, s)
		}
	}
	if len(survivors) > 0 {
		return CriterionResult{Status: CriterionViolated,
			Detail: "still present after the fix: " + strings.Join(survivors, ", ")}
	}
	return CriterionResult{Status: CriterionSatisfied,
		Detail: "removed and absent from the fixed file: " + strings.Join(targets, ", ")}
}

// checkPresence asserts at least one named symbol is present in the fixed file.
func checkPresence(symbols []string, patched string) CriterionResult {
	var found []string
	for _, s := range symbols {
		if strings.Contains(patched, s) {
			found = append(found, s)
		}
	}
	if len(found) > 0 {
		return CriterionResult{Status: CriterionSatisfied,
			Detail: "present in the fixed file: " + strings.Join(found, ", ")}
	}
	return CriterionResult{Status: CriterionNotCheckable,
		Detail: "named symbol absent, but it may belong to a file outside this patch"}
}

// namedSymbols extracts code-shaped identifiers from a criterion, de-duplicated
// and in first-seen order.
func namedSymbols(criterion string) []string {
	var found []string
	seen := map[string]bool{}
	for _, pattern := range symbolPatterns {
		for _, match := range pattern.FindAllStringSubmatch(criterion, -1) {
			if hit := match[1]; !seen[hit] {
				seen[hit] = true
				found = append(found, hit)
			}
		}
	}
	return found
}

// hasCue reports whether text contains any cue, case-insensitively.
func hasCue(text string, cues []string) bool {
	lowered := strings.ToLower(text)
	for _, cue := range cues {
		if strings.Contains(lowered, cue) {
			return true
		}
	}
	return false
}

// removedText concatenates the lines the patch deletes.
func removedText(patches []filePatch) string {
	var lines []string
	for _, patch := range patches {
		for _, line := range strings.Split(patch.Diff, "\n") {
			if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
				lines = append(lines, line[1:])
			}
		}
	}
	return strings.Join(lines, "\n")
}

// patchedText concatenates the post-fix content of every patched file.
func patchedText(patches []filePatch) string {
	contents := make([]string, 0, len(patches))
	for _, p := range patches {
		contents = append(contents, p.Content)
	}
	return strings.Join(contents, "\n")
}
