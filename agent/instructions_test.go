package agent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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

// aibom-android PRs #5-#9: every fixer "redacted" MainActivity's four Log.d
// calls by rewording their constant messages, and the rescan still flagged all
// of them. sherlock's static logging analyzer (analyzers/android/static/
// logging.py) reports ANY android.util.Log call in the app's own package whose
// tag and message are constants -- the call is the finding, not its text. v2
// deleted the calls and they cleared. MINIMAL ("never delete it") and CONTAINED
// ("reproduce verbatim every ... log") pushed the fixer into rewording, so the
// prompt must carve the flagged call out of both.
func TestFixSystemPrompt_removesACallThatIsItselfTheFinding(t *testing.T) {
	for _, want := range []string{"the call IS the finding", "rewording", "remove the call"} {
		if !strings.Contains(fixSystemPrompt, want) {
			t.Errorf("system prompt should say a flagged call is removed, not reworded: %q", want)
		}
	}
}

// KnoxIQ's Derived Crypto Keys remediation says "introduce a new utility class,
// SecureCryptoManager, into your project" and then calls it. The fixer read that
// as needing a new FILE, which it cannot create, so it declined the site and the
// finding never cleared on rescan. Java allows a second non-public top-level
// class -- or a nested one -- in the file it already has, so this is an edit.
func TestFixSystemPrompt_addsAPrescribedHelperClassToTheSameFile(t *testing.T) {
	for _, want := range []string{"BY NAME", "nested static class", "already created it: read it and call it"} {
		if !strings.Contains(fixSystemPrompt, want) {
			t.Errorf("system prompt should nest a named helper unless a NEW file carries it: %q", want)
		}
	}
	if !strings.Contains(fixSystemPrompt, "You create a file only when the target file is marked NEW") {
		t.Error("create_file exists only for NEW targets; the prompt must say so rather than let it assume")
	}
}

func TestFixUserPrompt_NewFileTargetAndOtherFiles(t *testing.T) {
	p := fixUserPrompt(FixRequest{Path: "app/src/main/res/xml/network_security_config.xml", Create: true})
	if !strings.Contains(p, "NEW - create it with create_file") {
		t.Errorf("a new-file target must say so: %s", p)
	}
	p = fixUserPrompt(FixRequest{Path: "app/src/main/AndroidManifest.xml",
		OtherFiles: []Target{{Path: "app/src/main/res/xml/network_security_config.xml", Why: "nsc", New: true}}})
	if !strings.Contains(p, "network_security_config.xml [NEW file, created before this call]") {
		t.Errorf("a new sibling file must be marked: %s", p)
	}
}

// The abstain clause must still refuse hand-rolled security machinery (it stopped
// a fixer writing 380 lines of APK signature parsing) WITHOUT also refusing the
// ordinary platform crypto calls a remediation spells out. Conflating the two
// makes every crypto remediation unfixable.
func TestFixSystemPrompt_separatesInventedCryptoFromDocumentedAPIs(t *testing.T) {
	if !strings.Contains(fixSystemPrompt, "implementing security machinery from memory") {
		t.Error("inventing a cipher, parser or verifier must still be refused")
	}
	for _, want := range []string{"NOT that", "invent the algorithm, the format, or the protocol"} {
		if !strings.Contains(fixSystemPrompt, want) {
			t.Errorf("documented platform crypto must stay permitted: %q", want)
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

func TestFixUserPrompt_WhyAndOtherFilesPrecedeRemediation(t *testing.T) {
	p := fixUserPrompt(FixRequest{
		Path: "app/src/main/AndroidManifest.xml", Finding: "StrandHogg",
		Remediation: "set taskAffinity and check isTaskRoot",
		Why:         `set taskAffinity="" on MainActivity`,
		OtherFiles:  []Target{{Path: "app/src/main/java/com/x/MainActivity.java", Why: "add isTaskRoot() check"}},
	})
	why := strings.Index(p, `Why this file: set taskAffinity="" on MainActivity`)
	header := strings.Index(p, "Other files in this remediation, handled in separate calls:")
	other := strings.Index(p, "  - app/src/main/java/com/x/MainActivity.java (add isTaskRoot() check)")
	rem := strings.Index(p, "Remediation:")
	require.True(t, why >= 0 && header > why && other > header && rem > other, p)
	require.Contains(t, p, "Apply only the part of the remediation that belongs in this file.")
}

func TestFixUserPrompt_NoTargetContextNoBlocks(t *testing.T) {
	p := fixUserPrompt(FixRequest{Path: "a/A.java", Finding: "f", Remediation: "r"})
	require.NotContains(t, p, "Why this file")
	require.NotContains(t, p, "Other files in this remediation")
}

// mfva 17: a rules file is appended to, never rewritten; the gate
// (checkRulesFileEdit) enforces the same list.
func TestFixSystemPrompt_rulesFileOnlyGainsRules(t *testing.T) {
	for _, want := range []string{"proguard-rules.pro) only ever gains rules", "-assumenosideeffects", "never add -include"} {
		if !strings.Contains(fixSystemPrompt, want) {
			t.Errorf("system prompt should bound rules-file edits: %q", want)
		}
	}
}
