package agent

import (
	"bytes"
	"context"
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

func TestReadFileHandler_ReadsFile(t *testing.T) {
	root := mfvaRepo(t)
	res, err := readFileHandler(root)(context.Background(),
		readFileInput{Path: "app/src/main/java/com/appknox/mfva/MainActivity.java"})
	require.NoError(t, err)
	require.NotNil(t, res.OfText)
	require.Contains(t, res.OfText.Text, "Random")
}

func TestReadFileHandler_RejectsTraversal(t *testing.T) {
	_, err := readFileHandler(mfvaRepo(t))(context.Background(),
		readFileInput{Path: "../../../../etc/passwd"})
	require.Error(t, err)
}

func TestGrepHandler_FindsPattern_SkippingBuildDir(t *testing.T) {
	root := mfvaRepo(t)
	res, err := grepHandler(root)(context.Background(), grepInput{Pattern: `new Random\(`})
	require.NoError(t, err)
	require.NotNil(t, res.OfText)
	require.Contains(t, res.OfText.Text, "MainActivity.java")
	require.NotContains(t, res.OfText.Text, "build/Generated.java") // pruned
}

func TestGrepHandler_InvalidRegex(t *testing.T) {
	_, err := grepHandler(mfvaRepo(t))(context.Background(), grepInput{Pattern: "("})
	require.Error(t, err)
}

func TestGlobHandler_MatchesBasename(t *testing.T) {
	root := mfvaRepo(t)
	res, err := globHandler(root)(context.Background(), globInput{Pattern: "*MainActivity*.java"})
	require.NoError(t, err)
	require.NotNil(t, res.OfText)
	require.Contains(t, res.OfText.Text, "com/appknox/mfva/MainActivity.java")
}

func TestBuildLocateTools_ReturnsThreeTools(t *testing.T) {
	tools, err := buildLocateTools(t.TempDir())
	require.NoError(t, err)
	require.Len(t, tools, 3)
}

func TestReadFileHandler_RejectsLeafSymlink(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("TOP-SECRET"), 0o644))
	require.NoError(t, os.Symlink(secret, filepath.Join(root, "creds.java")))

	_, err := readFileHandler(root)(context.Background(), readFileInput{Path: "creds.java"})
	require.Error(t, err)
}

func TestReadFileHandler_TruncatesLargeFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "Big.java"), bytes.Repeat([]byte("Z"), maxReadBytes+2048), 0o644))

	res, err := readFileHandler(root)(context.Background(), readFileInput{Path: "Big.java"})
	require.NoError(t, err)
	require.NotNil(t, res.OfText)
	require.Contains(t, res.OfText.Text, "truncated at")
	require.Less(t, len(res.OfText.Text), maxReadBytes+64) // capped, not the full 258KB
}

func TestGrepHandler_SkipsSymlinkedFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "In.java"), []byte("needle here\n"), 0o644))
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("needle SECRET-OUTSIDE\n"), 0o644))
	require.NoError(t, os.Symlink(secret, filepath.Join(root, "Link.java")))

	res, err := grepHandler(root)(context.Background(), grepInput{Pattern: "needle"})
	require.NoError(t, err)
	require.Contains(t, res.OfText.Text, "In.java")
	require.NotContains(t, res.OfText.Text, "SECRET-OUTSIDE") // symlink not followed
}

func TestGrepHandler_SkipsNonSourceDotfile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, ".env"), []byte("API_SECRET=abc\n"), 0o644))

	res, err := grepHandler(root)(context.Background(), grepInput{Pattern: "API_SECRET"})
	require.NoError(t, err)
	require.NotContains(t, res.OfText.Text, "API_SECRET") // dotfile is not source
}

func TestGrepHandler_SkipsOversizeFile(t *testing.T) {
	root := t.TempDir()
	big := append([]byte("BIGNEEDLE\n"), bytes.Repeat([]byte("a\n"), maxScanBytes)...)
	require.NoError(t, os.WriteFile(filepath.Join(root, "Big.java"), big, 0o644))

	res, err := grepHandler(root)(context.Background(), grepInput{Pattern: "BIGNEEDLE"})
	require.NoError(t, err)
	require.NotContains(t, res.OfText.Text, "BIGNEEDLE") // over maxScanBytes: skipped
}
