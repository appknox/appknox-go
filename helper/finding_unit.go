package helper

// FindingInputs is one finding of the Mycroft job, as the CLI sees it: its
// name and ids, never its remediation, which stays on the worker.
type FindingInputs struct {
	Finding string // vulnerability name

	// VulnerabilityID is the Appknox vulnerability this finding reports.
	// Printed on outcome lines.
	VulnerabilityID int

	// Severity is the analysis risk (Low, Medium, High, Critical). Empty when
	// this run has no analysis to read it from.
	Severity string

	// UnitID is Mycroft's id for this finding.
	UnitID string

	// Units are the findings to locate and fix, one each. Empty when the
	// finding is skipped.
	Units []FindingUnit

	// SkipReason says why Mycroft will not attempt this finding.
	SkipReason string

	// Skipped is one outcome line per finding dropped before it became a
	// Unit. Every finding gets exactly one outcome line (spec 3.4), so
	// fixSession.run appends these to Outcome.Findings alongside the ones
	// Units produces.
	Skipped []findingOutcome
}

// FindingUnit is one KnoxIQ finding: the unit a locate turn targets and whose
// remediation, and only whose remediation, reaches the fix turns. Sibling
// findings never share a fix turn (spec 3.3).
type FindingUnit struct {
	// UnitID is Mycroft's id for this finding; every turn names it.
	UnitID string
	Title  string
	// ThirdParty is KnoxIQ's is_third_party: the flagged code is a library.
	// The fix may still be the app's own (drop the dependency, remove its
	// use); a unit with no in-repo target is skipped as
	// reasonThirdPartyNoSource.
	ThirdParty bool
}

// unitsOf returns the units to run for one finding.
func unitsOf(in FindingInputs) []FindingUnit {
	return in.Units
}
