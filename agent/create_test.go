package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const nscRel = "app/src/main/res/xml/network_security_config.xml"

func TestCreateFile_CreatesOnlyItsPathAndNeverOverwrites(t *testing.T) {
	root := t.TempDir()

	_, err := createFile(root, nscRel, "app/src/main/res/xml/other.xml", "x")
	require.ErrorContains(t, err, "restricted to")

	res, err := createFile(root, nscRel, nscRel, "<network-security-config/>")
	require.NoError(t, err)
	require.Equal(t, "created "+nscRel, res)
	got, err := os.ReadFile(filepath.Join(root, nscRel))
	require.NoError(t, err)
	require.Equal(t, "<network-security-config/>", string(got))

	_, err = createFile(root, nscRel, nscRel, "overwrite")
	require.ErrorContains(t, err, "already exists")
	got, _ = os.ReadFile(filepath.Join(root, nscRel))
	require.Equal(t, "<network-security-config/>", string(got), "never overwritten")
}

func TestCreateFile_RefusesEscapingPath(t *testing.T) {
	root := t.TempDir()
	_, err := createFile(root, "../evil.xml", "../evil.xml", "x")
	require.Error(t, err)
	_, statErr := os.Stat(filepath.Join(filepath.Dir(root), "evil.xml"))
	require.True(t, os.IsNotExist(statErr))
}

// Review finding: with res/ a symlink to a directory outside the repository
// and res/xml/ missing, create_file must write nothing there, not even the
// xml/ directory.
func TestCreateFile_RefusesSymlinkedMissingParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app/src/main"), 0o755))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "app/src/main/res")))
	_, err := createFile(root, nscRel, nscRel, "x")
	require.Error(t, err)
	entries, readErr := os.ReadDir(outside)
	require.NoError(t, readErr)
	require.Empty(t, entries, "nothing created outside the repository")
}

func TestExecTool_RefusesWritesOnALocateTurn(t *testing.T) {
	root := t.TempDir()
	_, err := ExecTool(root, "edit", map[string]any{"path": "A.java", "old_string": "a", "new_string": "b"}, "")
	require.ErrorContains(t, err, "not available on a locate turn")
	_, err = ExecTool(root, "create_file", map[string]any{"path": nscRel, "content": "x"}, "")
	require.ErrorContains(t, err, "not available on a locate turn")
	_, err = ExecTool(root, "bash", nil, "A.java")
	require.ErrorContains(t, err, "unknown tool")
}
