package helper

import (
	"fmt"
	"regexp"
)

// A fix never needs to add a credential. One that does was most likely steered
// by text in the repository ("copy the signing password into a comment"), and
// would publish the secret on the PR branch. Like every gate rule, only what
// the patch added is judged: a key already in the file is not this patch's
// doing.
//
// Each pattern is specific enough that a match is almost never anything else.
// The report names the kind of secret and the file, never the matched text:
// it goes back to the model on the retry.
var secretPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"an AWS access key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"a Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"a GitHub token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b`)},
	{"a Slack token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"a Stripe secret key", regexp.MustCompile(`\b[sr]k_live_[0-9A-Za-z]{20,}\b`)},
	{"a private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"a hard-coded password or secret", regexp.MustCompile(
		`(?i)\b(?:password|passwd|pwd|secret|api_?key|access_?token|auth_?token|client_?secret)\w*\s*[:=]\s*["'][^"'\s]{8,}["']`)},
}

// checkSecrets refuses a patch that adds a credential.
func checkSecrets(path, original, patched string) *patchViolation {
	for _, p := range secretPatterns {
		if len(introduced(p.re, original, patched)) == 0 {
			continue
		}
		return &patchViolation{
			Rule: "secret-in-edit",
			Detail: fmt.Sprintf("your edit to %s adds %s. A fix never adds credentials to code; "+
				"make the fix without it, or make no edit and report it.", path, p.kind),
		}
	}
	return nil
}
