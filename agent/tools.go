package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The read-only tools a model turn may call on the checkout. Sherrinford
// defines them for the model; these run them, scoped to the repository root.

// readFile returns one repository file's content (CWE-22 guarded).
// Hidden files, credential files and file types the fix never needs are
// refused (see readable.go), judged on both the path asked for and the file a
// symlink inside the tree resolves to.
func readFile(root, path string) (string, error) {
	abs, err := resolveUnderRoot(root, path)
	if err != nil {
		return "", err
	}
	resolved, relErr := filepath.Rel(canonicalDir(root), abs)
	if relErr != nil || !readable(path) || !readable(resolved) {
		return "", fmt.Errorf(
			"agent: read_file %q: not readable by autofix (hidden, credential or unsupported file type)", path)
	}
	data, truncated, err := readCapped(abs, maxReadBytes)
	if err != nil {
		return "", fmt.Errorf("agent: read_file %q: %w", path, err)
	}
	text := string(data)
	if truncated {
		text += fmt.Sprintf("\n…[truncated at %d bytes]", maxReadBytes)
	}
	return text, nil
}

// grep returns "path:line:text" matches of pattern across real source files.
func grep(root, pattern string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("agent: grep pattern: %w", err)
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

// glob lists source files whose path or basename matches pattern.
func glob(root, pattern string) (string, error) {
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
		return "No files matched.", nil
	}
	return joinCapped(out, truncated), nil
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
