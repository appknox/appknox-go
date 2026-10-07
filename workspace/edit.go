package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CleanRel normalises a repo-relative path for comparison.
func CleanRel(p string) string { return filepath.ToSlash(filepath.Clean(p)) }

// Edit replaces old with new in rel, which must be allowedPath: the one file
// the current fix turn may change. old must occur exactly once so the edit is
// unambiguous. The change is written to disk (CWE-22 guarded).
func Edit(root, allowedPath, rel, old, new string) error {
	if CleanRel(rel) != CleanRel(allowedPath) {
		return fmt.Errorf("workspace: edit is restricted to %s (got %s)", allowedPath, rel)
	}
	abs, err := resolveUnderRoot(root, rel)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return err
	}
	content := string(data)
	switch strings.Count(content, old) {
	case 0:
		return fmt.Errorf("workspace: old_string not found in %s", rel)
	case 1:
		// unique — proceed
	default:
		return fmt.Errorf("workspace: old_string is not unique in %s; include more context", rel)
	}
	return os.WriteFile(abs, []byte(strings.Replace(content, old, new, 1)), 0o644)
}
