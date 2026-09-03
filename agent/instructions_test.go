package agent

import (
	"strings"
	"testing"
)

// Each rule below is here because its absence produced a measured defect --
// either on mfva, or in the 50-item compile bench described in instructions.go.

func TestFixSystemPrompt_forbidsTheOverReachThatBrokeTheBuild(t *testing.T) {
	// Dropping the "BC" provider changed the Cipher.getInstance overload and
	// invalidated an existing catch clause: ExportedActivity.java stopped
	// compiling.
	for _, want := range []string{"MINIMAL", "overload", "exception\n  surface"} {
		if !strings.Contains(fixSystemPrompt, want) {
			t.Errorf("system prompt should warn about %q", want)
		}
	}
}

// The overload rule used to end at "which does not compile". That taught the
// model the boundary was javac acceptance, so a patch that compiled but silently
// bound a different overload read as in-bounds -- one such patch sent a user
// session token in place of the provider key. The rule must be justified on
// runtime grounds, not compile grounds.
func TestFixSystemPrompt_treatsCompilingAsInsufficientEvidence(t *testing.T) {
	if strings.Contains(fixSystemPrompt, "which does not compile") {
		t.Error("justifying the overload rule by compilation is what let silent behaviour changes through")
	}
	for _, want := range []string{"Compiling is NOT", "credential", "different host"} {
		if !strings.Contains(fixSystemPrompt, want) {
			t.Errorf("system prompt should name the silent runtime divergence: %q", want)
		}
	}
}

// A KnoxIQ remediation is class-level policy prose naming manifests, build files
// and server behaviour the target file does not contain. Acting on those clauses
// was the single largest defect class: invented idle timeouts, invented caller
// guards, invented endpoints.
func TestFixSystemPrompt_boundsScopeToTheFile(t *testing.T) {
	for _, want := range []string{"SCOPE", "out of\n  scope", "Partial application"} {
		if !strings.Contains(fixSystemPrompt, want) {
			t.Errorf("system prompt should bound scope to the file: %q", want)
		}
	}
}

// Refusing to use a platform overload merely because the file does not declare
// it left a live SQL injection unfixed. Under-fixing is the dangerous direction.
func TestFixSystemPrompt_allowsUndeclaredPlatformOverloads(t *testing.T) {
	if !strings.Contains(fixSystemPrompt, "NOT an invention") {
		t.Error("a documented platform overload must not be treated as an invention")
	}
}

// Dead vulnerable code still trips the scanner that raised the finding, so an
// orphaned no-op TrustManager means the finding never clears on rescan.
func TestFixSystemPrompt_deletesOrphansThatAreThemselvesTheVulnerability(t *testing.T) {
	for _, want := range []string{"CONTAINED", "orphan", "still reported by the"} {
		if !strings.Contains(fixSystemPrompt, want) {
			t.Errorf("system prompt should carve dead vulnerable code out of the orphan rule: %q", want)
		}
	}
}

// Four fixers stated the defect in their own report and shipped it anyway.
func TestFixSystemPrompt_refusesToShipADisclosedGuess(t *testing.T) {
	for _, want := range []string{"Abstain per site", "does not make it acceptable"} {
		if !strings.Contains(fixSystemPrompt, want) {
			t.Errorf("disclosure must not substitute for abstention: %q", want)
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
