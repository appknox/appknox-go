package workspace

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const nscRel = "app/src/main/res/xml/network_security_config.xml"

func TestCreateFile_CreatesOnlyItsPathAndNeverOverwrites(t *testing.T) {
	root := t.TempDir()

	err := CreateFile(root, nscRel, "app/src/main/res/xml/other.xml", "x")
	require.ErrorContains(t, err, "restricted to")

	require.NoError(t, CreateFile(root, nscRel, nscRel, "<network-security-config/>"))
	got, err := os.ReadFile(filepath.Join(root, nscRel))
	require.NoError(t, err)
	require.Equal(t, "<network-security-config/>", string(got))

	err = CreateFile(root, nscRel, nscRel, "overwrite")
	require.ErrorContains(t, err, "already exists")
	got, _ = os.ReadFile(filepath.Join(root, nscRel))
	require.Equal(t, "<network-security-config/>", string(got), "never overwritten")
}

func TestCreateFile_RefusesEscapingPath(t *testing.T) {
	root := t.TempDir()
	require.Error(t, CreateFile(root, "../evil.xml", "../evil.xml", "x"))
	_, statErr := os.Stat(filepath.Join(filepath.Dir(root), "evil.xml"))
	require.True(t, os.IsNotExist(statErr))
}

// With res/ a symlink to a directory outside the repository and res/xml/
// missing, create_file must write nothing there, not even the xml/ directory.
func TestCreateFile_RefusesSymlinkedMissingParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app/src/main"), 0o755))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "app/src/main/res")))
	require.Error(t, CreateFile(root, nscRel, nscRel, "x"))
	entries, readErr := os.ReadDir(outside)
	require.NoError(t, readErr)
	require.Empty(t, entries, "nothing created outside the repository")
}
