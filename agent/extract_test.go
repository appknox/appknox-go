package agent

import (
	"os"
	"path/filepath"
	"testing"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	"github.com/stretchr/testify/require"
)

func repoWithMain(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "app/src/main/java/com/appknox/mfva")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "MainActivity.java"), []byte("x"), 0o644))
	return root
}

const mainRel = "app/src/main/java/com/appknox/mfva/MainActivity.java"

func TestExtractLocatedPath_RealFileUnderRoot(t *testing.T) {
	root := repoWithMain(t)
	require.Equal(t, mainRel, extractLocatedPath("The vulnerable file is `"+mainRel+"`.", root))
}

func TestExtractLocatedPath_StripsTrailingPunctuation(t *testing.T) {
	root := repoWithMain(t)
	require.Equal(t, mainRel, extractLocatedPath("path: "+mainRel+".", root))
}

func TestExtractLocatedPath_NoneForNonexistent(t *testing.T) {
	require.Equal(t, "", extractLocatedPath("src/Ghost.java", repoWithMain(t)))
}

func TestExtractLocatedPath_RejectsOutsideRoot(t *testing.T) {
	require.Equal(t, "", extractLocatedPath("/etc/passwd.java", repoWithMain(t)))
}

func TestExtractLocatedPath_IgnoresNonSource(t *testing.T) {
	require.Equal(t, "", extractLocatedPath("see README.md notes", repoWithMain(t)))
}

func TestExtractText_JoinsTextBlocks(t *testing.T) {
	msg := &anthropic.BetaMessage{Content: []anthropic.BetaContentBlockUnion{
		{Type: "text", Text: "app/A.java"},
		{Type: "tool_use"},
	}}
	require.Equal(t, "app/A.java\n", extractText(msg))
}

func TestExtractText_NilMessage(t *testing.T) {
	require.Equal(t, "", extractText(nil))
}

func TestExtractLocatedPath_PrefersConcludingPath(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app/src")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Helper.java"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Vuln.java"), []byte("x"), 0o644))

	text := "I first checked app/src/Helper.java but the issue is in app/src/Vuln.java"
	require.Equal(t, "app/src/Vuln.java", extractLocatedPath(text, root))
}
