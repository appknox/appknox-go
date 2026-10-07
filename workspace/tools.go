// Package workspace runs autofix tool calls against the CI checkout.
//
// The calls come from Appknox (the model asks to read, search or edit a file);
// this package executes them locally, confined to the repository root. It
// holds no prompt, no model and no network code: what to read or change is
// decided server-side, and only the results of these calls leave the machine.
package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Target is one repository file a remediation changes, with the part of the
// remediation it carries. New marks a file that does not exist yet.
type Target struct {
	Path string `json:"path"`
	Why  string `json:"why"`
	New  bool   `json:"new"`
}

// ReadFile returns a source file by repository-relative path (CWE-22 guarded),
// truncated at maxReadBytes with a marker.
func ReadFile(root, rel string) (string, error) {
	abs, err := resolveUnderRoot(root, rel)
	if err != nil {
		return "", err
	}
	data, truncated, err := readCapped(abs, maxReadBytes)
	if err != nil {
		return "", fmt.Errorf("workspace: read_file %q: %w", rel, err)
	}
	text := string(data)
	if truncated {
		text += fmt.Sprintf("\n…[truncated at %d bytes]", maxReadBytes)
	}
	return text, nil
}

// Grep returns "path:line:text" matches of an RE2 pattern across source files.
func Grep(root, pattern string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("workspace: grep pattern: %w", err)
	}
	out, truncated := grepFiles(root, re)
	if len(out) == 0 {
		return "No matches.", nil
	}
	return joinCapped(out, truncated), nil
}

// grepFiles walks source files under root collecting up to maxMatches "path:line"
// hits, skipping oversized files without reading them whole.
func grepFiles(root string, re *regexp.Regexp) ([]string, bool) {
	var out []string
	truncated := false
	walkSourceFiles(root, func(rel, abs string) error {
		if info, err := os.Stat(abs); err != nil || info.Size() > maxScanBytes {
			return nil
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			if re.MatchString(line) {
				out = append(out, fmt.Sprintf("%s:%d:%s", rel, i+1, strings.TrimSpace(line)))
				if len(out) >= maxMatches {
					truncated = true
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	return out, truncated
}

// Glob lists source files whose path or basename matches pattern.
func Glob(root, pattern string) string {
	var out []string
	truncated := false
	walkSourceFiles(root, func(rel, _ string) error {
		if globMatches(pattern, rel) {
			out = append(out, rel)
			if len(out) >= maxMatches {
				truncated = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	if len(out) == 0 {
		return "No files matched."
	}
	return joinCapped(out, truncated)
}

// joinCapped renders result lines, appending a marker when the cap was hit.
func joinCapped(lines []string, truncated bool) string {
	text := strings.Join(lines, "\n")
	if truncated {
		text += fmt.Sprintf("\n…[truncated at %d results — narrow the pattern]", maxMatches)
	}
	return text
}

// globMatches reports whether pattern matches the path or its basename.
func globMatches(pattern, rel string) bool {
	if ok, _ := filepath.Match(pattern, rel); ok {
		return true
	}
	ok, _ := filepath.Match(pattern, filepath.Base(rel))
	return ok
}
