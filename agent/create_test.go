package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const nscRel = "app/src/main/res/xml/network_security_config.xml"

func TestCreateHandler_CreatesOnlyItsPathAndNeverOverwrites(t *testing.T) {
	root := t.TempDir()
	var edits []editRecord
	create := createHandler(root, nscRel, &edits)

	_, err := create(context.Background(), createInput{Path: "app/src/main/res/xml/other.xml", Content: "x"})
	require.ErrorContains(t, err, "restricted to")

	_, err = create(context.Background(), createInput{Path: nscRel, Content: "<network-security-config/>"})
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(root, nscRel))
	require.NoError(t, err)
	require.Equal(t, "<network-security-config/>", string(got))
	require.Len(t, edits, 1)

	_, err = create(context.Background(), createInput{Path: nscRel, Content: "overwrite"})
	require.ErrorContains(t, err, "already exists")
	got, _ = os.ReadFile(filepath.Join(root, nscRel))
	require.Equal(t, "<network-security-config/>", string(got), "never overwritten")
}

func TestCreateHandler_RefusesEscapingPath(t *testing.T) {
	root := t.TempDir()
	var edits []editRecord
	_, err := createHandler(root, "../evil.xml", &edits)(context.Background(),
		createInput{Path: "../evil.xml", Content: "x"})
	require.Error(t, err)
	_, statErr := os.Stat(filepath.Join(filepath.Dir(root), "evil.xml"))
	require.True(t, os.IsNotExist(statErr))
}

// FixFile leaves disk as it found it: the new file and the directories it
// needed are gone again, and the content comes back in the result.
func TestCreateWith_RevertsByDeleting(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app/src/main/res/values"), 0o755))
	run := func(_ context.Context, _ Config, req FixRequest, edits *[]editRecord) error {
		_, err := createHandler(req.RepoRoot, req.Path, edits)(context.Background(),
			createInput{Path: req.Path, Content: "<network-security-config/>\n"})
		return err
	}
	res, err := fixWith(context.Background(), Config{}, FixRequest{RepoRoot: root, Path: nscRel, Create: true}, run)
	require.NoError(t, err)
	require.True(t, res.Changed)
	require.Equal(t, "<network-security-config/>\n", res.PatchedContent)
	_, statErr := os.Stat(filepath.Join(root, "app/src/main/res/xml"))
	require.True(t, os.IsNotExist(statErr), "the xml/ directory it created is removed too")
	_, statErr = os.Stat(filepath.Join(root, "app/src/main/res/values"))
	require.NoError(t, statErr, "directories that existed before stay")
}

func TestCreateWith_AbstainIsNoChange(t *testing.T) {
	root := t.TempDir()
	run := func(context.Context, Config, FixRequest, *[]editRecord) error { return nil }
	res, err := fixWith(context.Background(), Config{}, FixRequest{RepoRoot: root, Path: nscRel, Create: true}, run)
	require.NoError(t, err)
	require.False(t, res.Changed)
}

func TestCreateWith_RefusesExistingFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, filepath.Dir(nscRel)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, nscRel), []byte("keep"), 0o644))
	run := func(context.Context, Config, FixRequest, *[]editRecord) error { return nil }
	_, err := fixWith(context.Background(), Config{}, FixRequest{RepoRoot: root, Path: nscRel, Create: true}, run)
	require.ErrorContains(t, err, "not a new file")
	got, _ := os.ReadFile(filepath.Join(root, nscRel))
	require.Equal(t, "keep", string(got))
}

func TestParseTargetReply_NewFiles(t *testing.T) {
	r, err := parseTargetReply(`{"targets":[{"path":"app/src/main/AndroidManifest.xml","why":"reference it"}],` +
		`"new_files":[{"path":"` + nscRel + `","why":"cleartext off"}],"not_found":[],"needs_new_file":[]}`)
	require.NoError(t, err)
	require.Equal(t, []Target{{Path: nscRel, Why: "cleartext off"}}, r.NewFiles)
}

// Review finding: with res/ a symlink to a directory outside the repository
// and res/xml/ missing, create_file must write nothing there, not even the
// xml/ directory.
func TestCreateHandler_RefusesSymlinkedMissingParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app/src/main"), 0o755))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "app/src/main/res")))
	var edits []editRecord
	_, err := createHandler(root, nscRel, &edits)(context.Background(), createInput{Path: nscRel, Content: "x"})
	require.Error(t, err)
	entries, readErr := os.ReadDir(outside)
	require.NoError(t, readErr)
	require.Empty(t, entries, "nothing created outside the repository")
}

// A directory that gained other content stays, and so do its parents; only
// "not empty" is swallowed.
func TestRemoveCreated_LeavesNonEmptyDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "xml")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	file := filepath.Join(dir, "a.xml")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.xml"), []byte("y"), 0o644))

	require.NoError(t, removeCreated(file, []string{dir}))
	_, err := os.Stat(filepath.Join(dir, "other.xml"))
	require.NoError(t, err)
}
