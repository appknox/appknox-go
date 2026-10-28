package helper

import (
	"errors"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// repoRelPath turns an absolute path inside root into the repo-root relative,
// forward-slash form Mycroft stores (never a CI runner absolute path).
func repoRelPath(root, abs string) (string, error) {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", err
	}
	rel = filepath.ToSlash(rel)
	if err := validateRepoRelPath(rel); err != nil {
		return "", err
	}
	return rel, nil
}

func validateRepoRelPath(rel string) error {
	if rel == "" || rel == "." || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "./") ||
		strings.Contains(rel, "\\") || (len(rel) > 1 && rel[1] == ':') {
		return errors.New("path is not repo-root relative: " + rel)
	}
	for _, part := range strings.Split(rel, "/") {
		if part == ".." {
			return errors.New("path escapes the repository: " + rel)
		}
	}
	return nil
}

// absRepoPath maps a repo-relative path (from the server) back to disk,
// refusing anything outside root.
func absRepoPath(root, rel string) (string, error) {
	if err := validateRepoRelPath(rel); err != nil {
		return "", err
	}
	abs := filepath.Join(root, filepath.FromSlash(path.Clean(rel)))
	back, err := filepath.Rel(root, abs)
	if err != nil || strings.HasPrefix(back, "..") {
		return "", errors.New("path escapes the repository: " + rel)
	}
	return abs, nil
}

// globToRegexp supports "**" (any number of directories), "*" and "?".
func globToRegexp(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		ch := glob[i]
		switch {
		case strings.HasPrefix(glob[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(glob[i:], "**"):
			b.WriteString(".*")
			i++
		case ch == '*':
			b.WriteString("[^/]*")
		case ch == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// Files the CLI never reads, sends or writes (secrets / credentials).
var blockedFileRe = regexp.MustCompile(`(?i)(^|/)(\.env[^/]*|[^/]*\.(keystore|jks|p12|pfx|pem|key|mobileprovision|cer|der|p8)|google-services\.json|GoogleService-Info\.plist|local\.properties|secrets?\.[^/]+|credentials[^/]*|id_rsa[^/]*)$`)

// Directories skipped when listing / searching (generated, vendored, VCS).
// The agent can still read or change a path inside them by name.
var skippedDirRe = regexp.MustCompile(`(?i)^(\.git|\.gradle|\.idea|build|Pods|Carthage|DerivedData|node_modules|\.build|\.appknox|generated|intermediates)$`)
