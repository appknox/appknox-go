package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// In CI the workspace is not just the app. mfva's and aibom-android's workflows
// check appknox-go out INTO the workspace (actions/checkout with `path:
// appknox-go`), so the CLI's own source sits beside the app being scanned.
//
// Measured on aibom-android run 35772387479: 27 of 54 model calls had
// appknox-go/ in their context. Locate answered "Disabled SSL CA Validation"
// with appknox-go/appknox/appknox.go, and a grep for
// password|apikey|secret|API_KEY|SECRET returned ONLY appknox-go test files --
// so the finding never had a chance, and the tool budget was spent on the
// wrong repository.
//
// A directory carrying its own .git is a different repository. Nothing in it
// can be part of this app's fix, so the walk must not surface it.

// repoWithNestedCheckout builds root/ as a repo containing an app source file,
// plus root/appknox-go/ as a SEPARATE repo (its own .git) with its own source.
func repoWithNestedCheckout(t *testing.T) (root, appRel, nestedRel string) {
	t.Helper()
	root = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".git"), 0o755))

	appRel = filepath.Join("app", "src", "Main.kt")
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, appRel)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, appRel), []byte("val apiKey = \"x\"\n"), 0o644))

	nested := filepath.Join(root, "appknox-go")
	require.NoError(t, os.MkdirAll(filepath.Join(nested, ".git"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(nested, "appknox"), 0o755))
	nestedRel = filepath.Join("appknox-go", "appknox", "appknox.go")
	require.NoError(t, os.WriteFile(filepath.Join(root, nestedRel), []byte("const secret = \"y\"\n"), 0o644))
	return root, appRel, nestedRel
}

func collectWalked(root string) []string {
	var got []string
	walkSourceFiles(root, func(rel, _ string) error {
		got = append(got, filepath.ToSlash(rel))
		return nil
	})
	return got
}

func TestWalkSourceFiles_ExcludesNestedRepository(t *testing.T) {
	root, appRel, nestedRel := repoWithNestedCheckout(t)
	got := collectWalked(root)

	require.Contains(t, got, filepath.ToSlash(appRel),
		"the app's own source must still be walked")
	require.NotContains(t, got, filepath.ToSlash(nestedRel),
		"a directory with its own .git is a separate repository and must be pruned")
}

// The root itself carries .git -- that must not prune the entire walk, which
// would make the tool useless rather than merely mistargeted.
func TestWalkSourceFiles_RootRepoIsNotPruned(t *testing.T) {
	root, appRel, _ := repoWithNestedCheckout(t)
	require.Contains(t, collectWalked(root), filepath.ToSlash(appRel))
}

// A plain subdirectory with no .git is ordinary app code and stays in scope;
// the rule keys on the repository marker, not on nesting depth.
func TestWalkSourceFiles_KeepsOrdinarySubdirectories(t *testing.T) {
	root := t.TempDir()
	rel := filepath.Join("app", "src", "feature", "Detail.kt")
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte("class Detail\n"), 0o644))

	require.Contains(t, collectWalked(root), filepath.ToSlash(rel))
}

// A .git FILE (not a directory) is what a git worktree or submodule checkout
// leaves behind. It marks a separate repository just as a .git directory does.
func TestWalkSourceFiles_ExcludesWorktreeStyleNestedRepo(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "vendored-app")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(nested, ".git"),
		[]byte("gitdir: /elsewhere/.git/worktrees/x\n"), 0o644))
	rel := filepath.Join("vendored-app", "Main.kt")
	require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte("class Main\n"), 0o644))

	require.NotContains(t, collectWalked(root), filepath.ToSlash(rel),
		"a .git file marks a worktree/submodule checkout, also a separate repository")
}
