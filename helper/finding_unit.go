package helper

import (
	"strings"

	"github.com/appknox/appknox-go/appknox"
)

// FindingUnit is one KnoxIQ finding: the unit the locate agent targets and
// whose remediation, and only whose remediation, reaches the fixer. Sibling
// findings of the same analysis never share a fix call (spec 3.3).
type FindingUnit struct {
	Title           string
	Description     string
	Remediation     string // FixInstruction(f)
	DeveloperPrompt string
	Criteria        []string
	ClassHint       string // manual --class-hint path only
}

// unitsOf returns the units to run. Inputs built by knoxIQInputs carry one
// per KnoxIQ finding. Anything else (the manual --finding path, and callers
// that set only the aggregate fields) becomes a single unit, so both paths
// run through the same loop.
func unitsOf(in FindingInputs) []FindingUnit {
	if len(in.Units) > 0 {
		return in.Units
	}
	return []FindingUnit{{
		Remediation:     in.Remediation,
		DeveloperPrompt: in.DeveloperPrompt,
		Criteria:        in.Criteria,
		ClassHint:       strings.Join(in.ClassHints, ", "),
	}}
}

// unfixableReason says why KnoxIQ gave nothing to fix for an analysis, for
// its SKIPPED outcome line. Third-party wins over the other reasons because
// it is the product decision that applies whatever else is true.
func unfixableReason(all []*appknox.KnoxIQFinding) string {
	if len(all) == 0 {
		return "KnoxIQ: no findings"
	}
	for _, f := range all {
		if f != nil && f.Validation != nil && f.Validation.IsThirdParty != nil && *f.Validation.IsThirdParty {
			return "KnoxIQ: third-party code"
		}
	}
	for _, f := range all {
		if f == nil || f.Validation == nil {
			continue
		}
		v := f.Validation
		if v.Verdict == "FALSE_POSITIVE" || (v.IsValid != nil && !*v.IsValid) {
			return "KnoxIQ: false positive"
		}
	}
	return "KnoxIQ: not validated"
}
