package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEditHandler_AppliesUniqueReplace(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "A.java"), []byte("x = new Random();\n"), 0o644))
	var edits []editRecord
	res, err := editHandler(root, "A.java", &edits)(context.Background(),
		editInput{Path: "A.java", OldString: "new Random()", NewString: "new SecureRandom()"})
	require.NoError(t, err)
	require.NotNil(t, res.OfText)
	got, _ := os.ReadFile(filepath.Join(root, "A.java"))
	require.Contains(t, string(got), "SecureRandom")
	require.Len(t, edits, 1)
}

func TestEditHandler_NotFound(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "A.java"), []byte("hello"), 0o644))
	var edits []editRecord
	_, err := editHandler(root, "A.java", &edits)(context.Background(),
		editInput{Path: "A.java", OldString: "nope", NewString: "x"})
	require.Error(t, err)
	require.Empty(t, edits)
}

func TestEditHandler_NotUnique(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "A.java"), []byte("a\na\n"), 0o644))
	var edits []editRecord
	_, err := editHandler(root, "A.java", &edits)(context.Background(),
		editInput{Path: "A.java", OldString: "a", NewString: "b"})
	require.Error(t, err) // ambiguous — must include more context
}

func TestEditHandler_RejectsOtherPath(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "B.java"), []byte("secret"), 0o644))
	var edits []editRecord
	// allowed to edit A.java only; an attempt to edit B.java must be refused
	_, err := editHandler(root, "A.java", &edits)(context.Background(),
		editInput{Path: "B.java", OldString: "secret", NewString: "x"})
	require.Error(t, err)
	require.Empty(t, edits)
}

func TestEditHandler_RejectsTraversal(t *testing.T) {
	var edits []editRecord
	p := "../../../../etc/passwd"
	_, err := editHandler(t.TempDir(), p, &edits)(context.Background(),
		editInput{Path: p, OldString: "root", NewString: "x"})
	require.Error(t, err) // path matches allowedPath but resolveUnderRoot rejects the escape
}
