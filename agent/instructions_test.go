package agent

import (
	"strings"
	"testing"
)

// On the no-instructions branch the system prompt carries no fix rules: the
// remediation alone drives the edit. Guard that the experiment stays bare, and
// that the one operational line -- how to edit -- survives.
func TestFixSystemPrompt_carriesNoFixRules(t *testing.T) {
	for _, rule := range []string{"SCOPE", "WHERE", "ATOMIC", "MINIMAL", "COMPLETE", "COMPILABLE", "CONTAINED"} {
		if strings.Contains(fixSystemPrompt, rule) {
			t.Errorf("the no-instructions prompt must not carry the %s rule", rule)
		}
	}
	for _, want := range []string{"remediation", "str_replace", "Edit only the file"} {
		if !strings.Contains(fixSystemPrompt, want) {
			t.Errorf("system prompt should still say %q", want)
		}
	}
}

func TestFixUserPrompt_carriesTheDeveloperPromptWhenPresent(t *testing.T) {
	got := fixUserPrompt(FixRequest{
		Path: "app/Main.java", Finding: "Weak PRNG", Remediation: "use SecureRandom",
		DeveloperPrompt: "Replace Math.random() in the onClick handler",
	})
	if !strings.Contains(got, "Replace Math.random() in the onClick handler") {
		t.Error("KnoxIQ's developer guidance should reach the fixer")
	}
}

func TestFixUserPrompt_omitsEmptyOptionalSections(t *testing.T) {
	got := fixUserPrompt(FixRequest{Path: "a.java", Finding: "f", Remediation: "r"})
	if strings.Contains(got, "guidance for the developer") || strings.Contains(got, "checked against") {
		t.Errorf("absent sections must not appear as empty headings:\n%s", got)
	}
}

// Telling the model what it will be measured against beats letting it discover
// a miss after the fact.
func TestFixUserPrompt_showsTheCriteriaTheFixWillBeCheckedAgainst(t *testing.T) {
	got := fixUserPrompt(FixRequest{
		Path: "a.java", Finding: "f", Remediation: "r",
		Criteria: []string{"No Math.random() remains"},
	})
	if !strings.Contains(got, "No Math.random() remains") {
		t.Error("criteria should be visible to the fixer")
	}
}

func TestFixUserPrompt_asksForOneEditPerOccurrence(t *testing.T) {
	got := fixUserPrompt(FixRequest{Path: "a.java", Finding: "f", Remediation: "r"})
	if !strings.Contains(got, "one edit per occurrence") {
		t.Errorf("the per-file instruction should not imply a single edit:\n%s", got)
	}
}

// The fixer sees ONE file and cannot infer the build system from it. The
// profile must reach the model, and must arrive BEFORE the remediation,
// because it constrains how that remediation can be applied.
func TestFixUserPrompt_carriesTheProjectProfileBeforeTheRemediation(t *testing.T) {
	got := fixUserPrompt(FixRequest{
		Path: "a.kt", Finding: "f", Remediation: "wrap the log in BuildConfig.DEBUG",
		ProjectProfile: "Build system: Gradle / Android\nBuildConfig is NOT generated here",
	})
	if !strings.Contains(got, "BuildConfig is NOT generated here") {
		t.Fatalf("the project profile must be visible to the fixer:\n%s", got)
	}
	if strings.Index(got, "NOT generated here") > strings.Index(got, "Remediation:") {
		t.Errorf("the profile must precede the remediation it constrains:\n%s", got)
	}
}

// A repository with no readable build files produces an empty profile, and an
// empty profile must add no section at all rather than an empty heading.
func TestFixUserPrompt_omitsTheProfileSectionWhenUnknown(t *testing.T) {
	got := fixUserPrompt(FixRequest{Path: "a.java", Finding: "f", Remediation: "r"})
	if strings.Contains(got, "read from its build files") {
		t.Errorf("an empty profile should print no heading:\n%s", got)
	}
}
