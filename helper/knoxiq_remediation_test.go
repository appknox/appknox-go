package helper

import (
	"strings"
	"testing"

	"github.com/appknox/appknox-go/appknox"
)

func boolPtr(b bool) *bool { return &b }

// liveFinding mirrors analysis 11829 (Weak PRNG) on the UAT host: a TRUE_POSITIVE
// in first-party code, sourced from the KB entry v_android_weak_prng.
func liveFinding() *appknox.KnoxIQFinding {
	return &appknox.KnoxIQFinding{
		FindingID:   "F-1",
		Title:       "Activity := Lcom/appknox/mfva/MainActivity$3;",
		Description: "Weak PRNG in an onClick handler.",
		Remediation: &appknox.KnoxIQRemediation{
			Remediation:  "The application uses Math.random(); replace it with SecureRandom.",
			Steps:        []string{"Remove Insecure Random Number Generation", "Import SecureRandom"},
			CodeExamples: []string{"import java.security.SecureRandom;"},
			References:   []string{"https://cwe.mitre.org/data/definitions/338.html"},
			Verification: []string{"Confirm no Math.random() call remains"},
			Source:       map[string]interface{}{"source_type": "KB", "kb_id": "v_android_weak_prng"},
		},
		Validation: &appknox.KnoxIQValidation{
			Verdict:      "TRUE_POSITIVE",
			IsValid:      boolPtr(true),
			IsThirdParty: boolPtr(false),
		},
	}
}

func TestIsFixable_truePositiveFirstParty(t *testing.T) {
	if !IsFixable(liveFinding()) {
		t.Error("a TRUE_POSITIVE in first-party code must be fixable")
	}
}

func TestIsFixable_falsePositiveIsSkipped(t *testing.T) {
	f := liveFinding()
	f.Validation.Verdict = "FALSE_POSITIVE"
	f.Validation.IsValid = boolPtr(false)
	if IsFixable(f) {
		t.Error("a FALSE_POSITIVE must not be fixed")
	}
}

// KnoxIQ can mark a finding invalid without calling it a false positive.
func TestIsFixable_invalidIsSkipped(t *testing.T) {
	f := liveFinding()
	f.Validation.IsValid = boolPtr(false)
	if IsFixable(f) {
		t.Error("is_valid=false must not be fixed")
	}
}

// Patching a vendored library mis-locates and rewrites the wrong file.
func TestIsFixable_thirdPartyIsSkipped(t *testing.T) {
	f := liveFinding()
	f.Validation.IsThirdParty = boolPtr(true)
	if IsFixable(f) {
		t.Error("third-party code must not be fixed")
	}
}

func TestIsFixable_unknownThirdPartyIsNotThirdParty(t *testing.T) {
	f := liveFinding()
	f.Validation.IsThirdParty = nil
	if !IsFixable(f) {
		t.Error("unknown provenance must not be treated as third-party")
	}
}

// An absent is_valid is "not recorded", not "false". Go's zero value would
// otherwise silently mark every such finding unfixable.
func TestIsFixable_absentIsValidIsTreatedAsValid(t *testing.T) {
	f := liveFinding()
	f.Validation.IsValid = nil
	if !IsFixable(f) {
		t.Error("absent is_valid must fall through as valid, not default to false")
	}
}

// KnoxIQ records a validation for every finding it returns, so a missing one
// means something failed upstream. Editing code on the strength of a failure is
// the wrong direction.
func TestIsFixable_missingValidationIsSkipped(t *testing.T) {
	f := liveFinding()
	f.Validation = nil
	if IsFixable(f) {
		t.Error("a finding with no validation must not be fixed")
	}
}

// The API sends TRUE_POSITIVE and UNCERTAIN; uncertain findings are in scope by
// design, and the fix is reviewed as a draft PR.
func TestIsFixable_uncertainIsInScope(t *testing.T) {
	f := liveFinding()
	f.Validation.Verdict = "UNCERTAIN"
	if !IsFixable(f) {
		t.Error("UNCERTAIN findings are sent deliberately and must be fixable")
	}
}

func TestFixInstruction_usesKnoxIQWording(t *testing.T) {
	got := FixInstruction(liveFinding())
	for _, want := range []string{
		"Math.random()", "Steps:", "Remove Insecure Random", "Reference fix:", "SecureRandom",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("instruction missing %q:\n%s", want, got)
		}
	}
}

func TestFixInstruction_omitsAbsentSections(t *testing.T) {
	f := liveFinding()
	f.Remediation = &appknox.KnoxIQRemediation{Remediation: "Just the prose."}
	if got := FixInstruction(f); got != "Just the prose." {
		t.Errorf("got %q, want just the prose with no empty headings", got)
	}
}

func TestFixInstruction_fallsBackToDescription(t *testing.T) {
	f := liveFinding()
	f.Remediation = nil
	if got := FixInstruction(f); got != "Weak PRNG in an onClick handler." {
		t.Errorf("got %q, want the finding description", got)
	}
}

// The criteria a patch is checked against come straight from KnoxIQ.
func TestKnoxIQInputs_carriesVerificationAsCriteria(t *testing.T) {
	inputs := knoxIQInputs([]*appknox.KnoxIQFinding{liveFinding()}, "Insecure Random")
	if len(inputs.Criteria) != 1 || inputs.Criteria[0] != "Confirm no Math.random() call remains" {
		t.Errorf("criteria not carried through: %v", inputs.Criteria)
	}
	if !strings.Contains(inputs.Remediation, "SecureRandom") {
		t.Errorf("remediation not taken from KnoxIQ: %q", inputs.Remediation)
	}
	if inputs.Finding != "Insecure Random" {
		t.Errorf("Finding = %q, want the vulnerability name", inputs.Finding)
	}
}

// Class hints come from the finding titles, which carry the JVM descriptors.
func TestKnoxIQInputs_derivesClassHintsFromTitles(t *testing.T) {
	inputs := knoxIQInputs([]*appknox.KnoxIQFinding{liveFinding()}, "Insecure Random")
	if len(inputs.ClassHints) != 1 || inputs.ClassHints[0] != "com/appknox/mfva/MainActivity" {
		t.Errorf("ClassHints = %v, want [com/appknox/mfva/MainActivity]", inputs.ClassHints)
	}
}

// A finding stored before verification was carried through has no criteria.
// That must stay visible as "no criteria" so the caller can refuse to certify,
// rather than looking like a clean pass.
func TestKnoxIQInputs_absentVerificationLeavesNoCriteria(t *testing.T) {
	f := liveFinding()
	f.Remediation.Verification = nil
	inputs := knoxIQInputs([]*appknox.KnoxIQFinding{f}, "Insecure Random")
	if len(inputs.Criteria) != 0 {
		t.Errorf("want no criteria, got %v", inputs.Criteria)
	}
	if inputs.Remediation == "" {
		t.Error("remediation must still be present even without criteria")
	}
}
