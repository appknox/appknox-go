package workspace

import (
	"fmt"
	"os"
	"path/filepath"
)

// CreateFile creates rel, which must be allowedPath, and only when nothing is
// there yet: it never overwrites, so a misjudged "new" file cannot clobber the
// real one. Missing parent directories are created; the path is resolved under
// root first (CWE-22 / CWE-59), and the leaf is opened O_EXCL so a file or
// symlink appearing in between is refused rather than followed. Later changes
// go through Edit.
func CreateFile(root, allowedPath, rel, content string) error {
	if CleanRel(rel) != CleanRel(allowedPath) {
		return fmt.Errorf("workspace: create_file is restricted to %s (got %s)", allowedPath, rel)
	}
	abs, err := resolveUnderRoot(root, rel)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(abs); err == nil {
		return fmt.Errorf("workspace: %s already exists; use the edit tool to change it", rel)
	}
	// resolveUnderRoot can only canonicalise a parent that exists. Check the
	// deepest ancestor that does BEFORE MkdirAll follows it, and the full
	// parent again after, so a symlinked ancestor cannot take even an empty
	// directory, let alone the file, outside the repository.
	if err := parentStillUnderRoot(root, abs); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	if err := parentStillUnderRoot(root, abs); err != nil {
		return err
	}
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(content)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	return writeErr
}

// parentStillUnderRoot resolves the deepest existing ancestor of abs through
// every symlink and refuses it unless it is inside root.
func parentStillUnderRoot(root, abs string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	for {
		if _, statErr := os.Lstat(dir); statErr == nil || filepath.Dir(dir) == dir {
			break
		}
		dir = filepath.Dir(dir)
	}
	parent, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	if !underRoot(canonicalDir(absRoot), parent) {
		return fmt.Errorf("workspace: %s resolves outside the repository root", abs)
	}
	return nil
}
