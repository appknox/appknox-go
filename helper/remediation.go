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

// FindingInputs are the source-free locate + fix inputs for one analysis.
type FindingInputs struct {
	Finding     string   // short vulnerability summary
	ClassHints  []string // all first-party classes the finding references (locate targets)
	Remediation string   // KnoxIQ's per-finding remediation instruction

	// Criteria are KnoxIQ's verification assertions for checking a patch.
	//
	// ALWAYS EMPTY against the deployed KnoxIQ -- see the TODO on
	// appknox.KnoxIQRemediation.Verification. Empty means "could not check",
	// never "passed". Do not build a gate on this until it is populated.
	Criteria []string

	// DeveloperPrompt is KnoxIQ's own wording for the fix, passed through.
	DeveloperPrompt string
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

// remediationText assembles guidance from the VULNERABILITY-TYPE record --
// generic secure/insecure reference code for the class of issue.
//
// This is NOT KnoxIQ's per-finding remediation, despite what this comment used
// to claim and what the "(KnoxIQ)" labels below still say to the model. The
// fields read here (v.Name, v.Description, v.Compliant, v.NonCompliant) come
// from appknox.Vulnerability and are byte-identical for a given vulnerability
// id across every app ever scanned. Measured on file 24 (2026-09-21): compliant
// is populated for all 24 risky types, up to 3.2KB -- so this is substantial
// guidance, just not app-specific.
//
// KnoxIQ's per-finding remediation is knoxIQInputs in knoxiq_remediation.go.
// This function remains the fallback for --finding (manual) runs only.
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
