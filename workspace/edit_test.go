package workspace

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEdit_AppliesUniqueReplace(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "A.java"), []byte("x = new Random();\n"), 0o644))
	require.NoError(t, Edit(root, "A.java", "A.java", "new Random()", "new SecureRandom()"))
	got, _ := os.ReadFile(filepath.Join(root, "A.java"))
	require.Contains(t, string(got), "SecureRandom")
}

func TestEdit_NotFound(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "A.java"), []byte("hello"), 0o644))
	require.ErrorContains(t, Edit(root, "A.java", "A.java", "nope", "x"), "not found")
}

func TestEdit_NotUnique(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "A.java"), []byte("a\na\n"), 0o644))
	require.ErrorContains(t, Edit(root, "A.java", "A.java", "a", "b"), "not unique")
}

func TestEdit_RejectsOtherPath(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "B.java"), []byte("secret"), 0o644))
	// allowed to edit A.java only; an attempt to edit B.java must be refused
	require.ErrorContains(t, Edit(root, "A.java", "B.java", "secret", "x"), "restricted to")
	got, _ := os.ReadFile(filepath.Join(root, "B.java"))
	require.Equal(t, "secret", string(got))
}

func TestEdit_RejectsTraversal(t *testing.T) {
	p := "../../../../etc/passwd"
	// path matches allowedPath but resolveUnderRoot rejects the escape
	require.Error(t, Edit(t.TempDir(), p, p, "root", "x"))
}
