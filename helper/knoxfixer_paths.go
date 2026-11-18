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

// ensureNoSymlinkEscape rejects abs when it, or any existing ancestor
// directory on its path, is a symlink that resolves outside root. A
// committed symlink (file or directory) can point anywhere on disk, so the
// string check in validateRepoRelPath/absRepoPath is not enough.
func ensureNoSymlinkEscape(root, abs string) error {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	for cur := abs; ; {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			if real != rootReal && !strings.HasPrefix(real, rootReal+string(filepath.Separator)) {
				return errors.New("path escapes the repository via a symlink: " + abs)
			}
			return nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil
		}
		cur = parent
	}
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
// Secret-file-name matches (secrets, credentials) are anchored to the whole
// basename (optionally + a config extension) so they don't catch ordinary
// source files such as secrets.ts or CredentialsManager.java.
var blockedFileRe = regexp.MustCompile(`(?i)(^|/)(` +
	`\.env[^/]*` +
	`|\.npmrc|\.netrc|\.pypirc|\.git-credentials` +
	`|[^/]*\.(keystore|jks|p12|pfx|pem|key|mobileprovision|cer|der|p8|tfvars)` +
	`|google-services\.json|GoogleService-Info\.plist|local\.properties` +
	`|secrets?(\.(ya?ml|json|properties|env|txt|ini|toml))?` +
	`|credentials(\.(ya?ml|json|properties|env|txt|ini|toml))?` +
	`|id_rsa[^/]*` +
	`)$`)

// blockedWritePathRe: CI/build control files the agent can read for context
// but never create, edit or delete — a compromised build script here could
// run with the CI environment (including GITHUB_TOKEN) during verify.
var blockedWritePathRe = regexp.MustCompile(`(?i)^\.github(/.*)?$|^\.gitmodules$|^\.gitattributes$`)

// Directories skipped when listing / searching (generated, vendored, VCS).
// The agent can still read or change a path inside them by name.
var skippedDirRe = regexp.MustCompile(`(?i)^(\.git|\.gradle|\.idea|build|Pods|Carthage|DerivedData|node_modules|\.build|\.appknox|generated|intermediates)$`)

// isDotGitPath reports whether rel is (or is inside) a ".git" entry,
// case-insensitively — .Git/config resolves to the real .git directory on
// the case-insensitive filesystems macOS and Windows runners typically use.
func isDotGitPath(rel string) bool {
	lower := strings.ToLower(rel)
	return lower == ".git" || strings.HasPrefix(lower, ".git/")
}
