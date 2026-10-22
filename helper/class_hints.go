package helper

import (
	"regexp"
	"strings"

	"github.com/appknox/appknox-go/appknox"
)

// Class hints for --list-analyses: the first-party classes each analysis's
// finding text names, so a developer can see what a finding points at.

var (
	descriptorRE = regexp.MustCompile(`L([A-Za-z_][\w/]*(?:\$[\w]+)*);`)
	// frameworkPrefixes mark non-first-party classes (not the app's own source).
	frameworkPrefixes = []string{"android/", "androidx/", "java/", "javax/", "kotlin/", "kotlinx/"}
)

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
