package agent

import (
	"strings"
	"testing"
)

// Each rule below is here because its absence produced a real defect on mfva.

func TestFixSystemPrompt_forbidsTheOverReachThatBrokeTheBuild(t *testing.T) {
	// Dropping the "BC" provider changed the Cipher.getInstance overload and
	// invalidated an existing catch clause: ExportedActivity.java stopped
	// compiling.
	for _, want := range []string{"MINIMAL", "overload", "catch clause", "does not compile"} {
		if !strings.Contains(fixSystemPrompt, want) {
			t.Errorf("system prompt should warn about %q", want)
		}
	}
}

func TestFixSystemPrompt_demandsEveryOccurrence(t *testing.T) {
	// The old prompt asked for "a SINGLE precise fix", so a finding covering two
	// Math.random() sites got one of them fixed.
	if !strings.Contains(fixSystemPrompt, "COMPLETE") {
		t.Error("system prompt should require every occurrence to be fixed")
	}
	if strings.Contains(fixSystemPrompt, "SINGLE precise") {
		t.Error("the single-edit instruction is what caused the half-fix; it must be gone")
	}
}

func TestFixSystemPrompt_requiresTheResultToCompile(t *testing.T) {
	if !strings.Contains(fixSystemPrompt, "COMPILABLE") {
		t.Error("system prompt should require the file to still compile")
	}
}

func TestFixSystemPrompt_prefersNoFixOverABadOne(t *testing.T) {
	if !strings.Contains(fixSystemPrompt, "make NO edit") {
		t.Error("an unsafe fix must be declined, not guessed at")
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
