package helper

import (
	"testing"

	"github.com/appknox/appknox-go/appknox"
	"github.com/stretchr/testify/require"
)

func TestKnoxIQInputs_OneUnitPerFindingWithItsOwnRemediation(t *testing.T) {
	a := &appknox.KnoxIQFinding{Title: "Logs in com.x.A", Description: "dA", DeveloperPrompt: "pA",
		Remediation: &appknox.KnoxIQRemediation{Remediation: "remove the log in A",
			Verification: []string{"no Log call in A"}}}
	b := &appknox.KnoxIQFinding{Title: "Logs in com.x.B", Description: "dB",
		Remediation: &appknox.KnoxIQRemediation{Remediation: "remove the log in B"}}

	in := knoxIQInputs([]*appknox.KnoxIQFinding{a, b}, "Application Logs")

	require.Len(t, in.Units, 2)
	require.Equal(t, FindingUnit{
		Title: "Logs in com.x.A", Description: "dA", Remediation: "remove the log in A",
		DeveloperPrompt: "pA", Criteria: []string{"no Log call in A"},
	}, in.Units[0])
	require.Equal(t, "remove the log in B", in.Units[1].Remediation)
	require.Empty(t, in.Units[0].ClassHint, "KnoxIQ units carry full text, not descriptor hints")
	require.Contains(t, in.Remediation, "remove the log in A", "the aggregate stays for the fixable filter")
}

func TestKnoxIQInputs_NilRemediationStillAUnit(t *testing.T) {
	in := knoxIQInputs([]*appknox.KnoxIQFinding{{Title: "T", Description: "D"}}, "V")
	require.Len(t, in.Units, 1)
	require.Equal(t, "D", in.Units[0].Remediation)
}

// TestKnoxIQInputs_EmptyFixInstructionGetsSkipLine is F1's second half: a
// finding whose FixInstruction is empty (no title, description, or
// remediation at all) used to be dropped from Units with no trace. It must
// still produce its own SKIPPED outcome line.
func TestKnoxIQInputs_EmptyFixInstructionGetsSkipLine(t *testing.T) {
	in := knoxIQInputs([]*appknox.KnoxIQFinding{
		{Title: "Has text", Description: "D"},
		{}, // Title, Description and Remediation all empty -> FixInstruction is ""
	}, "Weak Crypto")

	require.Len(t, in.Units, 1, "the empty finding must not become a unit")
	require.Equal(t, []findingOutcome{{
		Finding: "Weak Crypto", Title: "", Status: statusSkipped, Detail: "KnoxIQ: no remediation text",
	}}, in.Skipped)
}

func TestUnitsOf_SynthesizesOneUnitForAggregateInputs(t *testing.T) {
	u := unitsOf(FindingInputs{Finding: "Weak PRNG", ClassHints: []string{"com/x/A", "com/x/B"},
		Remediation: "r", DeveloperPrompt: "p", Criteria: []string{"c"}})
	require.Equal(t, []FindingUnit{{Remediation: "r", DeveloperPrompt: "p",
		Criteria: []string{"c"}, ClassHint: "com/x/A, com/x/B"}}, u)
}

func TestUnitsOf_KeepsExplicitUnits(t *testing.T) {
	units := []FindingUnit{{Title: "a"}, {Title: "b"}}
	require.Equal(t, units, unitsOf(FindingInputs{Remediation: "r", Units: units}))
}

func TestUnfixableReason(t *testing.T) {
	yes, no := true, false
	require.Equal(t, "KnoxIQ: no findings", unfixableReason(nil))
	third := &appknox.KnoxIQFinding{Validation: &appknox.KnoxIQValidation{IsThirdParty: &yes}}
	require.Equal(t, "KnoxIQ: third-party code", unfixableReason([]*appknox.KnoxIQFinding{third}))
	fp := &appknox.KnoxIQFinding{Validation: &appknox.KnoxIQValidation{IsValid: &no}}
	require.Equal(t, "KnoxIQ: false positive", unfixableReason([]*appknox.KnoxIQFinding{fp}))
	verdict := &appknox.KnoxIQFinding{Validation: &appknox.KnoxIQValidation{Verdict: "FALSE_POSITIVE"}}
	require.Equal(t, "KnoxIQ: false positive", unfixableReason([]*appknox.KnoxIQFinding{verdict}))
	require.Equal(t, "KnoxIQ: not validated", unfixableReason([]*appknox.KnoxIQFinding{{Title: "t"}}))
}
