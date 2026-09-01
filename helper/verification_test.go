package helper

import (
	"strings"
	"testing"
)

// fixedPRNG is the patch the live UAT run actually produced for analysis 11829:
// both Math.random() call sites replaced with SecureRandom.
func fixedPRNG() filePatch {
	return filePatch{
		Path: "app/src/main/java/com/appknox/mfva/MainActivity.java",
		Diff: `--- app/src/main/java/com/appknox/mfva/MainActivity.java
-                String key = keys[(int) (Math.random() * keys.length)];
+                java.security.SecureRandom secureRandomKeys = new java.security.SecureRandom();
+                String key = keys[secureRandomKeys.nextInt(keys.length)];`,
		Content: `package com.appknox.mfva;
import java.security.SecureRandom;
public class MainActivity {
    void onClick() {
        java.security.SecureRandom secureRandomKeys = new java.security.SecureRandom();
        String key = keys[secureRandomKeys.nextInt(keys.length)];
    }
}`,
	}
}

// brokenPRNG claims to fix the finding but leaves Math.random() in place. This
// is the case a security gate must never call satisfied.
func brokenPRNG() filePatch {
	p := fixedPRNG()
	p.Content = `package com.appknox.mfva;
import java.security.SecureRandom;
public class MainActivity {
    void onClick() {
        String key = keys[(int) (Math.random() * keys.length)];
    }
}`
	return p
}

// liveCriteria are real KnoxIQ verification steps -- note they carry NO
// backticks, which is the format that once defeated a backtick-only extractor.
var liveCriteria = []string{
	"Confirm that all Math.random() calls in security-sensitive paths have been replaced with SecureRandom.nextInt()",
	"Run static analysis to confirm no remaining Math.random() or java.util.Random imports in MainActivity.java",
	"Rebuild and test the onClick handler to confirm the app functions correctly",
}

func TestCheckCriteria_satisfiedWhenSymbolRemoved(t *testing.T) {
	report := checkCriteria([]filePatch{fixedPRNG()}, liveCriteria[:1])
	if len(report.Satisfied()) != 1 {
		t.Fatalf("want 1 satisfied, got %s (%+v)", report.Summary(), report.Results)
	}
}

// The whole point of the gate.
func TestCheckCriteria_violatedWhenSymbolSurvives(t *testing.T) {
	report := checkCriteria([]filePatch{brokenPRNG()}, liveCriteria[:1])
	if len(report.Violated()) != 1 {
		t.Fatalf("a surviving Math.random() must be VIOLATED, got %s", report.Summary())
	}
}

// A step with no code symbol is honest about being undecidable rather than
// counted as a pass.
func TestCheckCriteria_manualStepIsNotCheckable(t *testing.T) {
	report := checkCriteria([]filePatch{fixedPRNG()}, liveCriteria[2:])
	if len(report.Results) != 1 || report.Results[0].Status != CriterionNotCheckable {
		t.Fatalf("manual step must be not_checkable, got %+v", report.Results)
	}
	if report.Checked() != 0 {
		t.Errorf("not_checkable must not count as checked, got %d", report.Checked())
	}
}

// Location hints like MainActivity$3 name a symbol the patch never deleted.
// Treating them as removal targets would invent verdicts.
func TestCheckCriteria_locationHintIsNotARemovalTarget(t *testing.T) {
	report := checkCriteria([]filePatch{fixedPRNG()},
		[]string{"Confirm the finding in MainActivity.onClick() is no longer present"})
	if report.Results[0].Status == CriterionViolated {
		t.Errorf("a symbol the patch never removed must not be judged violated: %+v", report.Results[0])
	}
}

func TestCheckCriteria_presenceSatisfiedWhenSymbolAdded(t *testing.T) {
	report := checkCriteria([]filePatch{fixedPRNG()},
		[]string{"Verify that java.security.SecureRandom is imported"})
	if len(report.Satisfied()) != 1 {
		t.Fatalf("want the import to satisfy a presence check, got %s (%+v)",
			report.Summary(), report.Results)
	}
}

// Presence cues must stay strict phrases. A loose keyword would let a criterion
// that really asserts ABSENCE match the presence branch and report a surviving
// insecure call as satisfied -- a wrong pass, which is the worst outcome here.
func TestCheckCriteria_absenceWordingNeverReadsAsPresence(t *testing.T) {
	report := checkCriteria([]filePatch{brokenPRNG()},
		[]string{"Confirm Math.random() is no longer present in MainActivity.java"})
	if report.Results[0].Status == CriterionSatisfied {
		t.Errorf("absence wording must never yield satisfied while the symbol survives: %+v",
			report.Results[0])
	}
}

func TestCheckCriteria_mixedLiveSetReportsHonestCounts(t *testing.T) {
	report := checkCriteria([]filePatch{fixedPRNG()}, liveCriteria)
	if len(report.Results) != 3 {
		t.Fatalf("want 3 results, got %d", len(report.Results))
	}
	if report.Checked() >= len(report.Results) {
		t.Errorf("the manual step must remain unchecked: %s", report.Summary())
	}
	if len(report.Violated()) != 0 {
		t.Errorf("a correct fix must not violate anything: %+v", report.Violated())
	}
}

func TestCheckCriteria_emptyCriteriaYieldsEmptyReport(t *testing.T) {
	report := checkCriteria([]filePatch{fixedPRNG()}, nil)
	if len(report.Results) != 0 || report.Checked() != 0 {
		t.Errorf("no criteria must produce nothing to check, got %s", report.Summary())
	}
}

// The gate is the point of the whole step: before this, validation existed but
// nothing consulted it.

func TestVerificationGate_allowsAVerifiedPatch(t *testing.T) {
	report := checkCriteria([]filePatch{fixedPRNG()}, liveCriteria)
	if err := VerificationGate(report, len(liveCriteria)); err != nil {
		t.Errorf("a patch satisfying KnoxIQ's criteria must be deliverable: %v", err)
	}
}

func TestVerificationGate_refusesAViolatedPatch(t *testing.T) {
	report := checkCriteria([]filePatch{brokenPRNG()}, liveCriteria)
	err := VerificationGate(report, len(liveCriteria))
	if err == nil {
		t.Fatal("a patch that leaves Math.random() in place must NOT be delivered")
	}
	if !strings.Contains(err.Error(), "still present after the fix") {
		t.Errorf("the error should name what survived, got: %v", err)
	}
}

// Findings analysed before the storage fix carry no criteria. Unchecked is not
// a pass -- this is the failure mode we already shipped once.
func TestVerificationGate_refusesWhenNoCriteriaExist(t *testing.T) {
	report := checkCriteria([]filePatch{fixedPRNG()}, nil)
	err := VerificationGate(report, 0)
	if err == nil {
		t.Fatal("a patch with no criteria must not be certified")
	}
	if !strings.Contains(err.Error(), "no verification criteria") {
		t.Errorf("the error should explain why, got: %v", err)
	}
}

// Criteria exist but every one is a manual step: still undecidable, still not a pass.
func TestVerificationGate_refusesWhenNothingIsDecidable(t *testing.T) {
	manual := []string{"Rebuild and test the app on a device"}
	report := checkCriteria([]filePatch{fixedPRNG()}, manual)
	if err := VerificationGate(report, len(manual)); err == nil {
		t.Error("undecidable criteria must not be treated as satisfied")
	}
}

func TestCheckCriteria_blankCriteriaAreSkipped(t *testing.T) {
	report := checkCriteria([]filePatch{fixedPRNG()}, []string{"", "   "})
	if len(report.Results) != 0 {
		t.Errorf("blank criteria must be skipped, got %+v", report.Results)
	}
}
