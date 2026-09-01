package helper

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/appknox/appknox-go/appknox"
)

var (
	tagRE        = regexp.MustCompile(`<[^>]+>`)
	descriptorRE = regexp.MustCompile(`L([A-Za-z_][\w/]*(?:\$[\w]+)*);`)
	// frameworkPrefixes mark non-first-party classes (not the app's own source).
	frameworkPrefixes = []string{"android/", "androidx/", "java/", "javax/", "kotlin/", "kotlinx/"}
	langBySuffix      = map[string]string{
		".java": "java", ".kt": "kotlin", ".swift": "swift", ".m": "objective-c",
		".mm": "objective-c", ".js": "javascript", ".ts": "typescript",
		".c": "c", ".cpp": "cpp", ".h": "c", ".xml": "xml",
	}
)

// FindingInputs are the source-free locate + fix inputs derived from an analysis.
type FindingInputs struct {
	Finding     string   // short vulnerability summary
	ClassHints  []string // all first-party classes the finding references (locate targets)
	Remediation string   // source-free remediation guidance

	// Criteria are KnoxIQ's own verification steps -- what a generated patch is
	// checked against before delivery.
	//
	// Empty means "could not check", NOT "nothing to check": findings analysed
	// before the storage layer stopped discarding the field carry none. A caller
	// with no criteria must refuse to certify the patch rather than assume it
	// passed.
	Criteria []string
}

// stripHTML removes tags for source-free remediation text.
func stripHTML(s string) string {
	return strings.TrimSpace(tagRE.ReplaceAllString(s, " "))
}

// detectLanguage returns a best-effort language name from the file extension.
func detectLanguage(filename string) string {
	return langBySuffix[strings.ToLower(filepath.Ext(filename))]
}

// classHintsFromFindings returns all DISTINCT first-party class paths referenced
// by the finding descriptors, e.g. Lcom/appknox/mfva/MainActivity$6;-> ->
// com/appknox/mfva/MainActivity. Multi-class findings yield more than one.
func classHintsFromFindings(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range descriptorRE.FindAllStringSubmatch(text, -1) {
		top := strings.SplitN(m[1], "$", 2)[0]
		if top == "" || hasAnyPrefix(top, frameworkPrefixes) || seen[top] {
			continue
		}
		seen[top] = true
		out = append(out, top)
	}
	return out
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// deriveFindingInputs assembles the finding summary, class hint, and source-free
// remediation from an Appknox analysis and its vulnerability (KnoxIQ).
func deriveFindingInputs(a *appknox.Analysis, v *appknox.Vulnerability) FindingInputs {
	return FindingInputs{
		Finding:     v.Name,
		ClassHints:  classHintsFromFindings(findingsText(a)),
		Remediation: remediationText(a, v),
	}
}

// findingsText joins the finding titles/descriptions for hint extraction.
func findingsText(a *appknox.Analysis) string {
	var b strings.Builder
	for _, f := range a.Findings {
		b.WriteString(f.Title)
		b.WriteByte(' ')
		b.WriteString(f.Description)
		b.WriteByte('\n')
	}
	return b.String()
}

// remediationText assembles source-free guidance from the VULNERABILITY-TYPE
// record — generic reference code for the class of issue, NOT KnoxIQ's
// per-finding remediation, despite what this comment used to claim.
//
// NO PRODUCTION CALLER. Autofix now takes remediation from KnoxIQ and fails
// rather than degrading to this (see fetchAppknoxInputs), so it and
// deriveFindingInputs survive only for their tests. Retained pending a decision
// on whether hosts without KnoxIQ should be supported at all; delete both if
// the answer is no.
//
// Never includes the client's source — only finding metadata and the
// secure/insecure code references attached to the vulnerability.
func remediationText(a *appknox.Analysis, v *appknox.Vulnerability) string {
	parts := []string{"Vulnerability: " + v.Name}
	if len(a.Cwe) > 0 {
		parts = append(parts, "CWE: "+strings.Join(a.Cwe, ", "))
	}
	if d := stripHTML(v.Description); d != "" {
		parts = append(parts, d)
	}
	if c := stripHTML(v.Compliant); c != "" {
		parts = append(parts, "Secure code reference (KnoxIQ):\n"+c)
	}
	if nc := stripHTML(v.NonCompliant); nc != "" {
		parts = append(parts, "Insecure pattern to replace (KnoxIQ):\n"+nc)
	}
	return strings.Join(parts, "\n\n")
}
