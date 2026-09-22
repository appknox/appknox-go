package helper

import (
	"strings"
	"testing"

	"github.com/appknox/appknox-go/appknox"
)

func boolPtr(b bool) *bool { return &b }

// finding builds a KnoxIQ finding with a present validation, the normal case.
func finding(title string, v *appknox.KnoxIQValidation) *appknox.KnoxIQFinding {
	return &appknox.KnoxIQFinding{Title: title, Validation: v}
}

func TestIsFixable_MissingValidationIsNotFixable(t *testing.T) {
	if IsFixable(&appknox.KnoxIQFinding{Title: "x"}) {
		t.Fatal("no validation means we could not establish the finding is real")
	}
	if IsFixable(nil) {
		t.Fatal("nil finding is not fixable")
	}
}

func TestIsFixable_UncertainIsInScope(t *testing.T) {
	f := finding("x", &appknox.KnoxIQValidation{Verdict: "UNCERTAIN"})
	if !IsFixable(f) {
		t.Fatal("UNCERTAIN findings are sent deliberately and land in a draft PR")
	}
}

func TestIsFixable_ThirdPartyIsSkipped(t *testing.T) {
	f := finding("x", &appknox.KnoxIQValidation{
		Verdict: "TRUE_POSITIVE", IsThirdParty: boolPtr(true)})
	if IsFixable(f) {
		t.Fatal("a vendored library cannot be patched in the customer tree")
	}
}

func TestIsFixable_UnknownThirdPartyIsNotThirdParty(t *testing.T) {
	f := finding("x", &appknox.KnoxIQValidation{Verdict: "TRUE_POSITIVE"})
	if !IsFixable(f) {
		t.Fatal("nil IsThirdParty means unknown, and unknown is not third-party")
	}
}

func TestIsFixable_ExplicitInvalidIsSkipped(t *testing.T) {
	f := finding("x", &appknox.KnoxIQValidation{
		Verdict: "TRUE_POSITIVE", IsValid: boolPtr(false)})
	if IsFixable(f) {
		t.Fatal("an explicitly invalid finding must not be touched")
	}
}

func TestFixInstruction_AssemblesKnoxIQSections(t *testing.T) {
	f := &appknox.KnoxIQFinding{
		Remediation: &appknox.KnoxIQRemediation{
			Remediation:  "Use AES/GCM.",
			Steps:        []string{"Replace ECB", "Add an IV"},
			CodeExamples: []string{"Cipher.getInstance(\"AES/GCM/NoPadding\")"},
		},
	}
	got := FixInstruction(f)
	for _, want := range []string{"Use AES/GCM.", "- Replace ECB", "- Add an IV", "AES/GCM/NoPadding"} {
		if !strings.Contains(got, want) {
			t.Errorf("instruction missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestFixInstruction_EmptySectionsAreOmitted(t *testing.T) {
	f := &appknox.KnoxIQFinding{
		Remediation: &appknox.KnoxIQRemediation{Remediation: "Just this."},
	}
	got := FixInstruction(f)
	if strings.Contains(got, "Steps:") || strings.Contains(got, "Reference fix:") {
		t.Fatalf("empty sections must not emit bare headings, got:\n%s", got)
	}
}

func TestFixInstruction_FallsBackToDescription(t *testing.T) {
	f := &appknox.KnoxIQFinding{Title: "T", Description: "D"}
	if got := FixInstruction(f); got != "D" {
		t.Fatalf("want description fallback, got %q", got)
	}
}

func TestKnoxIQInputs_MergesFindingsAndDedupesHints(t *testing.T) {
	mk := func(desc string) *appknox.KnoxIQFinding {
		return &appknox.KnoxIQFinding{
			Title:           "Weak crypto in Lcom/x/A;",
			Description:     desc,
			DeveloperPrompt: "prompt",
			Remediation:     &appknox.KnoxIQRemediation{Remediation: "fix it"},
		}
	}
	in := knoxIQInputs([]*appknox.KnoxIQFinding{mk("Lcom/x/A;"), mk("Lcom/x/A;")}, "Derived Crypto Keys")

	if in.Finding != "Derived Crypto Keys" {
		t.Errorf("Finding should be the vulnerability name, got %q", in.Finding)
	}
	if len(in.ClassHints) != 1 {
		t.Errorf("duplicate class hints must collapse, got %v", in.ClassHints)
	}
	if in.Remediation == "" {
		t.Error("remediation must carry KnoxIQ's instruction")
	}
	if in.DeveloperPrompt == "" {
		t.Error("developer prompt must be preserved")
	}
}
