package agent

import (
	"fmt"
	"os"
	"path/filepath"
)

// createFile creates path, which must be allowedPath, with its complete
// content, and only when nothing is there yet: it never overwrites, so a model
// that misjudged a file as new cannot clobber the real one. Missing parent
// directories are created; the path is resolved under root first (CWE-22 /
// CWE-59), and the leaf is opened O_EXCL so a file or symlink appearing in
// between is refused rather than followed. Later changes to the new file go
// through editFile.
func createFile(root, allowedPath, path, content string) (string, error) {
	if cleanRel(path) != cleanRel(allowedPath) {
		return "", fmt.Errorf("agent: create_file is restricted to %s (got %s)", allowedPath, path)
	}
	abs, err := resolveUnderRoot(root, path)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(abs); err == nil {
		return "", fmt.Errorf("agent: %s already exists; use the edit tool to change it", path)
	}
	// resolveUnderRoot can only canonicalise a parent that exists. Check
	// the deepest ancestor that does BEFORE MkdirAll follows it, and the
	// full parent again after, so a symlinked ancestor cannot take even
	// an empty directory, let alone the file, outside the repository.
	if err := parentStillUnderRoot(root, abs); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", err
	}
	if err := parentStillUnderRoot(root, abs); err != nil {
		return "", err
	}
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	_, writeErr := f.WriteString(content)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return "", writeErr
	}
	return "created " + path, nil
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
		return fmt.Errorf("agent: %s resolves outside the repository root", abs)
	}
	return nil
}
