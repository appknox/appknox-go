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

// Files the CLI never reads or sends (secrets / credentials).
var blockedFileRe = regexp.MustCompile(`(?i)(^|/)(\.env[^/]*|[^/]*\.(keystore|jks|p12|pfx|pem|key|mobileprovision|cer|der|p8)|google-services\.json|GoogleService-Info\.plist|local\.properties|secrets?\.[^/]+|credentials[^/]*|id_rsa[^/]*)$`)

// Directories never walked or edited (generated, vendored, VCS).
var skippedDirRe = regexp.MustCompile(`(?i)^(\.git|\.gradle|\.idea|build|Pods|Carthage|DerivedData|node_modules|\.build|\.appknox|generated|intermediates)$`)

// Paths never edited by the CLI (CI config, Xcode project files, generated).
var blockedEditRe = regexp.MustCompile(`(?i)(^|/)(\.github|\.gitlab-ci\.yml|\.circleci|Jenkinsfile|bitrise\.yml|fastlane|build|Pods|Carthage|DerivedData|generated)(/|$)|\.pbxproj$|\.xcodeproj(/|$)|\.xcworkspace(/|$)|(^|/)R\.java$|(^|/)BuildConfig\.java$`)

func isHiddenPath(rel string) bool {
	for _, part := range strings.Split(rel, "/") {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

func isReadableRepoFile(rel string) bool {
	return !blockedFileRe.MatchString(rel) && !isHiddenPath(rel)
}

func isEditableRepoFile(rel string) bool {
	return isReadableRepoFile(rel) && !blockedEditRe.MatchString(rel)
}
