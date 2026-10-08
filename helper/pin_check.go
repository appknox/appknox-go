package helper

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// pinRE finds a network security config <pin> and its digest text.
var pinRE = regexp.MustCompile(`<pin\b[^>]*>\s*([^<]*?)\s*</pin>`)

// checkAddedPins rejects a network security config patch that adds a <pin>
// whose digest is not a real SHA-256 SPKI hash: a placeholder satisfies the
// scanner while the app refuses every TLS connection to the domain (eShop 83).
// The fixer cannot know a server's key, so a pin the remediation does not
// give is never written.
func checkAddedPins(p, original, patched string) *patchViolation {
	if !strings.EqualFold(filepath.Ext(p), ".xml") || !strings.Contains(patched, "<network-security-config") {
		return nil
	}
	had := map[string]bool{}
	for _, m := range pinRE.FindAllStringSubmatch(original, -1) {
		had[m[1]] = true
	}
	for _, m := range pinRE.FindAllStringSubmatch(patched, -1) {
		if had[m[1]] || realPinDigest(m[1]) {
			continue
		}
		return &patchViolation{
			Rule: "placeholder-pin",
			Detail: fmt.Sprintf("%s adds <pin>%s</pin>, which is not a real server key digest: the app would "+
				"refuse every connection to that domain. Add no <pin-set> unless the remediation gives the "+
				"digest; make the rest of the fix (cleartext off, no user or overridden trust anchors).", p, m[1]),
		}
	}
	return nil
}

// realPinDigest reports a base64 SHA-256 digest that is not a filler pattern:
// a real hash uses many distinct characters.
func realPinDigest(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return false
	}
	distinct := map[rune]bool{}
	for _, r := range strings.TrimRight(s, "=") {
		distinct[r] = true
	}
	return len(distinct) >= 12
}
