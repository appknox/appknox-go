package helper

import "testing"

// --allow-unverified ships a fix KnoxIQ gave us no way to check. It must never
// ship one that demonstrably fails a check: "could not check" is a gap in our
// inputs, "failed" is a broken fix.

func TestAllowUnverified_shipsWhenThereAreNoCriteria(t *testing.T) {
	report := checkCriteria([]filePatch{fixedPRNG()}, nil)
	if err := VerificationGateAllowingUnverified(report, 0); err != nil {
		t.Errorf("no criteria should be allowed through with the flag: %v", err)
	}
}

func TestAllowUnverified_shipsWhenNothingIsDecidable(t *testing.T) {
	manual := []string{"Rebuild and test the app on a device"}
	report := checkCriteria([]filePatch{fixedPRNG()}, manual)
	if err := VerificationGateAllowingUnverified(report, len(manual)); err != nil {
		t.Errorf("undecidable criteria should be allowed through with the flag: %v", err)
	}
}

// The flag is an escape hatch for missing inputs, never for a broken fix.
func TestAllowUnverified_stillRefusesAViolatedPatch(t *testing.T) {
	report := checkCriteria([]filePatch{brokenPRNG()}, liveCriteria)
	err := VerificationGateAllowingUnverified(report, len(liveCriteria))
	if err == nil {
		t.Fatal("a demonstrably failing patch must NOT ship, flag or no flag")
	}
	if !contains(err.Error(), "still present after the fix") {
		t.Errorf("the refusal should name what survived, got: %v", err)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
