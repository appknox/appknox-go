package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// cleanRel normalises a repo-relative path for comparison.
func cleanRel(p string) string { return filepath.ToSlash(filepath.Clean(p)) }

// editFile replaces oldString with newString in path, which must be
// allowedPath (the one file a fix turn may change). The change is applied on
// disk (CWE-22 guarded). oldString must be unique so the edit is unambiguous.
func editFile(root, allowedPath, path, oldString, newString string) (string, error) {
	if cleanRel(path) != cleanRel(allowedPath) {
		return "", fmt.Errorf("agent: edit is restricted to %s (got %s)", allowedPath, path)
	}
	abs, err := resolveUnderRoot(root, path)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	content := string(data)
	switch strings.Count(content, oldString) {
	case 0:
		return "", fmt.Errorf("agent: old_string not found in %s", path)
	case 1:
		// unique — proceed
	default:
		return "", fmt.Errorf("agent: old_string is not unique in %s; include more context", path)
	}
	updated := strings.Replace(content, oldString, newString, 1)
	if err := os.WriteFile(abs, []byte(updated), 0o644); err != nil {
		return "", err
	}
	return "edited " + path, nil
}
