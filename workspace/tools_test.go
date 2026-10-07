package workspace

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// mfvaRepo writes a minimal checkout with one locatable source file.
func mfvaRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "app/src/main/java/com/appknox/mfva")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "MainActivity.java"),
		[]byte("int r = new Random().nextInt();\n"), 0o644))
	// A build dir that must never be searched.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "build"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "build/Generated.java"), []byte("new Random()"), 0o644))
	return root
}

func TestReadFile_ReadsFile(t *testing.T) {
	root := mfvaRepo(t)
	res, err := ReadFile(root, "app/src/main/java/com/appknox/mfva/MainActivity.java")
	require.NoError(t, err)
	require.Contains(t, res, "Random")
}

func TestReadFile_RejectsTraversal(t *testing.T) {
	_, err := ReadFile(mfvaRepo(t), "../../../../etc/passwd")
	require.Error(t, err)
}

func TestGrep_FindsPattern_SkippingBuildDir(t *testing.T) {
	root := mfvaRepo(t)
	res, err := Grep(root, `new Random\(`)
	require.NoError(t, err)
	require.Contains(t, res, "MainActivity.java")
	require.NotContains(t, res, "build/Generated.java") // pruned
}

func TestGrep_InvalidRegex(t *testing.T) {
	_, err := Grep(mfvaRepo(t), "(")
	require.Error(t, err)
}

func TestGlob_MatchesBasename(t *testing.T) {
	root := mfvaRepo(t)
	res := Glob(root, "*MainActivity*.java")
	require.Contains(t, res, "com/appknox/mfva/MainActivity.java")
}

func TestReadFile_RejectsLeafSymlink(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("TOP-SECRET"), 0o644))
	require.NoError(t, os.Symlink(secret, filepath.Join(root, "creds.java")))

	_, err := ReadFile(root, "creds.java")
	require.Error(t, err)
}

func TestReadFile_TruncatesLargeFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "Big.java"), bytes.Repeat([]byte("Z"), maxReadBytes+2048), 0o644))

	res, err := ReadFile(root, "Big.java")
	require.NoError(t, err)
	require.Contains(t, res, "truncated at")
	require.Less(t, len(res), maxReadBytes+64) // capped, not the full 258KB
}

func TestGrep_SkipsSymlinkedFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "In.java"), []byte("needle here\n"), 0o644))
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("needle SECRET-OUTSIDE\n"), 0o644))
	require.NoError(t, os.Symlink(secret, filepath.Join(root, "Link.java")))

	res, err := Grep(root, "needle")
	require.NoError(t, err)
	require.Contains(t, res, "In.java")
	require.NotContains(t, res, "SECRET-OUTSIDE") // symlink not followed
}

func TestGrep_SkipsNonSourceDotfile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, ".env"), []byte("API_SECRET=abc\n"), 0o644))

	res, err := Grep(root, "API_SECRET")
	require.NoError(t, err)
	require.NotContains(t, res, "API_SECRET") // dotfile is not source
}

func TestGrep_SkipsOversizeFile(t *testing.T) {
	root := t.TempDir()
	big := append([]byte("BIGNEEDLE\n"), bytes.Repeat([]byte("a\n"), maxScanBytes)...)
	require.NoError(t, os.WriteFile(filepath.Join(root, "Big.java"), big, 0o644))

	res, err := Grep(root, "BIGNEEDLE")
	require.NoError(t, err)
	require.NotContains(t, res, "BIGNEEDLE") // over maxScanBytes: skipped
}
