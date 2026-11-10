package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveUnderRoot_ValidPath(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sub/A.java"), []byte("x"), 0o644))

	abs, err := resolveUnderRoot(root, "sub/A.java")
	require.NoError(t, err)
	require.True(t, filepath.IsAbs(abs))
	require.FileExists(t, abs)
}

func TestResolveUnderRoot_RejectsAbsolute(t *testing.T) {
	_, err := resolveUnderRoot(t.TempDir(), "/etc/passwd")
	require.Error(t, err)
}

func TestResolveUnderRoot_RejectsTraversal(t *testing.T) {
	_, err := resolveUnderRoot(t.TempDir(), "../escape.java")
	require.Error(t, err)
}

func TestResolveUnderRoot_RejectsEmpty(t *testing.T) {
	_, err := resolveUnderRoot(t.TempDir(), "")
	require.Error(t, err)
}

func TestResolveUnderRoot_RejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "link")))

	_, err := resolveUnderRoot(root, "link/evil.java")
	require.Error(t, err)
}

func TestResolveUnderRoot_RejectsLeafSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("outside"), 0o644))
	// A symlink FILE directly inside the root whose target is outside must be rejected.
	require.NoError(t, os.Symlink(secret, filepath.Join(root, "creds.xml")))

	_, err := resolveUnderRoot(root, "creds.xml")
	require.Error(t, err)
}

func TestResolveUnderRoot_AllowsInRootSymlink(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "real.java"), []byte("x"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(root, "real.java"), filepath.Join(root, "alias.java")))

	abs, err := resolveUnderRoot(root, "alias.java")
	require.NoError(t, err)
	require.FileExists(t, abs)
}
