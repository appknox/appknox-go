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
	Finding     string // short vulnerability summary
	ClassHint   string // class/symbol hint for the locate agent
	Remediation string // source-free remediation guidance (KnoxIQ)
}

// stripHTML removes tags for source-free remediation text.
func stripHTML(s string) string {
	return strings.TrimSpace(tagRE.ReplaceAllString(s, " "))
}

// detectLanguage returns a best-effort language name from the file extension.
func detectLanguage(filename string) string {
	return langBySuffix[strings.ToLower(filepath.Ext(filename))]
}

// classHintFromFindings returns the first first-party class path referenced by a
// finding descriptor, e.g. Lcom/appknox/mfva/MainActivity$6;-> -> com/appknox/mfva/MainActivity.
func classHintFromFindings(text string) string {
	for _, m := range descriptorRE.FindAllStringSubmatch(text, -1) {
		top := strings.SplitN(m[1], "$", 2)[0]
		if top == "" || hasAnyPrefix(top, frameworkPrefixes) {
			continue
		}
		return top
	}
	return ""
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
		ClassHint:   classHintFromFindings(findingsText(a)),
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

// remediationText assembles source-free remediation guidance (KnoxIQ) — never
// the client's source, only finding metadata + secure/insecure code references.
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
