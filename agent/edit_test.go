package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEditFile_AppliesUniqueReplace(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "A.java"), []byte("x = new Random();\n"), 0o644))
	res, err := editFile(root, "A.java", "A.java", "new Random()", "new SecureRandom()")
	require.NoError(t, err)
	require.Equal(t, "edited A.java", res)
	got, _ := os.ReadFile(filepath.Join(root, "A.java"))
	require.Contains(t, string(got), "SecureRandom")
}

func TestEditFile_NotFound(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "A.java"), []byte("hello"), 0o644))
	_, err := editFile(root, "A.java", "A.java", "nope", "x")
	require.Error(t, err)
	got, _ := os.ReadFile(filepath.Join(root, "A.java"))
	require.Equal(t, "hello", string(got))
}

func TestEditFile_NotUnique(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "A.java"), []byte("a\na\n"), 0o644))
	_, err := editFile(root, "A.java", "A.java", "a", "b")
	require.Error(t, err) // ambiguous — must include more context
}

func TestEditFile_RejectsOtherPath(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "B.java"), []byte("secret"), 0o644))
	// allowed to edit A.java only; an attempt to edit B.java must be refused
	_, err := editFile(root, "A.java", "B.java", "secret", "x")
	require.Error(t, err)
	got, _ := os.ReadFile(filepath.Join(root, "B.java"))
	require.Equal(t, "secret", string(got))
}

func TestEditFile_RejectsTraversal(t *testing.T) {
	p := "../../../../etc/passwd"
	_, err := editFile(t.TempDir(), p, p, "root", "x")
	require.Error(t, err) // path matches allowedPath but resolveUnderRoot rejects the escape
}
