package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSafeDest_Valid(t *testing.T) {
	root := t.TempDir()
	dest, err := safeDest(root, "app/Main.java")
	require.NoError(t, err)
	// safeDest canonicalises symlinks (e.g. macOS /var -> /private/var).
	canonicalRoot, _ := filepath.EvalSymlinks(root)
	require.Equal(t, filepath.Join(canonicalRoot, "app/Main.java"), dest)
}

func TestSafeDest_RejectsTraversalAndAbsolute(t *testing.T) {
	root := t.TempDir()
	_, err := safeDest(root, "../escape.java")
	require.Error(t, err)
	_, err = safeDest(root, "/etc/passwd")
	require.Error(t, err)
	_, err = safeDest(root, "")
	require.Error(t, err)
}

func TestSafeDest_RejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("x"), 0o644))
	require.NoError(t, os.Symlink(secret, filepath.Join(root, "link.java")))
	_, err := safeDest(root, "link.java")
	require.Error(t, err) // must not resolve to a file outside root
}

func TestSafeDest_RejectsNonExistentThroughSymlinkedAncestor(t *testing.T) {
	// An ancestor symlink pointing outside root must be rejected even when the
	// leaf (and intermediate dirs) do not exist yet.
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "link")))
	_, err := safeDest(root, "link/deep/new.java")
	require.Error(t, err)
}

func TestApplyPatch_WritesUnderRoot(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, applyPatch(root, "sub/A.java", "fixed\n"))
	got, err := os.ReadFile(filepath.Join(root, "sub/A.java"))
	require.NoError(t, err)
	require.Equal(t, "fixed\n", string(got))
}

func TestApplyPatch_RejectsTraversal(t *testing.T) {
	require.Error(t, applyPatch(t.TempDir(), "../evil.java", "x"))
}

func TestReadUnderRoot(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "A.java"), []byte("hello"), 0o644))
	got, err := readUnderRoot(root, "A.java")
	require.NoError(t, err)
	require.Equal(t, "hello", got)

	_, err = readUnderRoot(root, "../escape")
	require.Error(t, err)
}
