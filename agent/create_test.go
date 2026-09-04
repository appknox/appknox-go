package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateHandler_WritesNewFileAndRecordsIt(t *testing.T) {
	root := t.TempDir()
	var created []createdFile
	h := createHandler(root, &created)

	_, err := h(context.Background(), createInput{
		Path:    "app/src/main/java/com/appknox/mfva/SecureCryptoManager.java",
		Content: "class SecureCryptoManager {}\n",
	})
	require.NoError(t, err)

	require.Len(t, created, 1)
	require.Equal(t, "app/src/main/java/com/appknox/mfva/SecureCryptoManager.java", created[0].Path)
	onDisk, readErr := os.ReadFile(filepath.Join(root, created[0].Path))
	require.NoError(t, readErr)
	require.Equal(t, "class SecureCryptoManager {}\n", string(onDisk))
}

// The edit tool is restricted to the one located file. If create could
// overwrite, that restriction would be trivially bypassable.
func TestCreateHandler_RefusesToOverwriteExistingFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "Main.java"), []byte("original\n"), 0o644))
	var created []createdFile

	_, err := createHandler(root, &created)(context.Background(),
		createInput{Path: "Main.java", Content: "replaced\n"})

	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
	require.Empty(t, created)
	onDisk, _ := os.ReadFile(filepath.Join(root, "Main.java"))
	require.Equal(t, "original\n", string(onDisk), "the existing file must be untouched")
}

func TestCreateHandler_RejectsPathOutsideRoot(t *testing.T) {
	root := t.TempDir()
	var created []createdFile

	for _, path := range []string{"../escape.java", "/etc/passwd"} {
		_, err := createHandler(root, &created)(context.Background(),
			createInput{Path: path, Content: "x\n"})
		require.Error(t, err, "path %q should be rejected", path)
	}
	require.Empty(t, created)
}

func TestCreateHandler_RejectsEmptyContent(t *testing.T) {
	root := t.TempDir()
	var created []createdFile

	_, err := createHandler(root, &created)(context.Background(),
		createInput{Path: "Empty.java", Content: "   \n"})

	require.Error(t, err)
	require.Empty(t, created)
}

// A remediation names one helper. A fix wanting many is restructuring the
// project, which is a developer's decision, not autofix's.
func TestCreateHandler_CapsTheNumberOfNewFiles(t *testing.T) {
	root := t.TempDir()
	var created []createdFile
	h := createHandler(root, &created)

	for i := 0; i < maxCreatedFiles; i++ {
		_, err := h(context.Background(), createInput{
			Path: filepath.Join("app", string(rune('A'+i))+".java"), Content: "class X {}\n"})
		require.NoError(t, err)
	}
	_, err := h(context.Background(), createInput{Path: "app/OneTooMany.java", Content: "class Y {}\n"})

	require.Error(t, err)
	require.Contains(t, err.Error(), "at most")
	require.Len(t, created, maxCreatedFiles)
}

func TestCreateHandler_CapsFileSize(t *testing.T) {
	root := t.TempDir()
	var created []createdFile

	_, err := createHandler(root, &created)(context.Background(), createInput{
		Path: "app/Huge.java", Content: strings.Repeat("x", maxCreatedFileBytes+1)})

	require.Error(t, err)
	require.Empty(t, created)
	_, statErr := os.Stat(filepath.Join(root, "app/Huge.java"))
	require.True(t, os.IsNotExist(statErr), "an oversize file must not be written")
}

func TestRemoveCreated_DeletesEveryCreatedFile(t *testing.T) {
	root := t.TempDir()
	var created []createdFile
	h := createHandler(root, &created)
	for _, p := range []string{"app/One.java", "app/Two.java"} {
		_, err := h(context.Background(), createInput{Path: p, Content: "class X {}\n"})
		require.NoError(t, err)
	}

	require.NoError(t, removeCreated(root, created))

	for _, f := range created {
		_, err := os.Stat(filepath.Join(root, f.Path))
		require.True(t, os.IsNotExist(err), "%s should be gone", f.Path)
	}
}

// Removal runs on every path out of a fix, including ones where the file is
// already gone. It must not turn that into an error.
func TestRemoveCreated_IgnoresAlreadyDeletedFile(t *testing.T) {
	require.NoError(t, removeCreated(t.TempDir(), []createdFile{{Path: "app/Never.java"}}))
}
