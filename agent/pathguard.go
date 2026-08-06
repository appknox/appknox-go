package agent

import (
	"fmt"
	"path/filepath"
	"strings"
)

// resolveUnderRoot resolves a repository-relative path against root and returns
// its absolute, symlink-canonicalised location, refusing anything that escapes
// the repository root (CWE-22 / CWE-59). Absolute inputs, `..` traversal, and
// symlinks whose target lands outside the root — whether the symlink is a parent
// directory OR the leaf file itself — are all rejected, even when the leaf does
// not exist yet.
func resolveUnderRoot(root, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", fmt.Errorf("agent: non-relative path %q rejected", rel)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("agent: resolve root %q: %w", root, err)
	}
	absRoot = canonicalDir(absRoot)

	target := filepath.Join(absRoot, rel)
	// Canonicalise the parent so a symlinked directory cannot escape even when the
	// leaf does not exist yet, then canonicalise the full path so a symlinked leaf
	// file (which os.ReadFile/os.Stat would follow) also cannot escape.
	target = filepath.Join(canonicalDir(filepath.Dir(target)), filepath.Base(target))
	if resolved, err := filepath.EvalSymlinks(target); err == nil {
		target = resolved
	}
	if !underRoot(absRoot, target) {
		return "", fmt.Errorf("agent: path %q escapes repo root", rel)
	}
	return target, nil
}

// underRoot reports whether target is absRoot itself or nested beneath it.
func underRoot(absRoot, target string) bool {
	rel, err := filepath.Rel(absRoot, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// canonicalDir returns the symlink-resolved path when it exists, else the input.
func canonicalDir(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return p
}
