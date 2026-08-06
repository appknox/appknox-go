package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// safeDest resolves filename under root, rejecting path traversal and symlinks
// that escape the root (CWE-22 / CWE-59). It canonicalises the deepest existing
// ancestor — so a symlinked directory anywhere in the chain cannot escape the
// root even when the leaf file does not exist yet — and returns the resolved
// absolute path. Sound as a standalone guard (does not rely on the caller
// having read the file first).
func safeDest(root, filename string) (string, error) {
	if filename == "" || filepath.IsAbs(filename) {
		return "", fmt.Errorf("refusing non-relative path: %q", filename)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absRoot = resolveDeepest(absRoot)

	dest := resolveDeepest(filepath.Join(absRoot, filename))
	rel, err := filepath.Rel(absRoot, dest)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing to write outside repo root: %s", filename)
	}
	return dest, nil
}

// resolveDeepest canonicalises the longest existing prefix of p (following
// symlinks) and re-appends the remaining non-existent components — so no symlink
// in the ancestor chain can redirect the final path outside the root.
func resolveDeepest(p string) string {
	rest := ""
	for {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			if rest == "" {
				return resolved
			}
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(p)
		if parent == p { // hit the filesystem root without resolving anything
			return filepath.Join(p, rest)
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}

// readUnderRoot reads a repo-relative file, path-guarded.
func readUnderRoot(root, filename string) (string, error) {
	dest, err := safeDest(root, filename)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// applyPatch writes patched content back to filename under root, path-guarded.
func applyPatch(root, filename, content string) error {
	dest, err := safeDest(root, filename)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, []byte(content), 0o644)
}
