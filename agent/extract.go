package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	anthropic "github.com/anthropics/anthropic-sdk-go"
)

var pathToken = regexp.MustCompile(`[\w./\\-]+`)

// extractText concatenates the text blocks of a model message.
func extractText(msg *anthropic.BetaMessage) string {
	if msg == nil {
		return ""
	}
	var b strings.Builder
	for _, block := range msg.Content {
		if block.Type == "text" && block.Text != "" {
			b.WriteString(block.Text)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// extractLocatedPath returns the repo-relative source path named in text, or ""
// to abstain. It prefers the LAST valid token so a concluding answer wins over
// any files the model merely mentioned while narrating, and it rejects tokens
// that are non-source, do not exist, or resolve outside root (CWE-22).
func extractLocatedPath(text, root string) string {
	found := ""
	for _, tok := range pathToken.FindAllString(text, -1) {
		rel := strings.Trim(tok, "`'\"")
		rel = strings.TrimRight(rel, ".,;:")
		rel = strings.ReplaceAll(rel, "\\", "/")
		if rel == "" || !isSource(rel) {
			continue
		}
		abs, err := resolveUnderRoot(root, rel)
		if err != nil {
			continue
		}
		if info, err := os.Stat(abs); err == nil && !info.IsDir() {
			found = filepath.ToSlash(filepath.Clean(rel))
		}
	}
	return found
}
