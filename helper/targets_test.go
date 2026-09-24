package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/stretchr/testify/require"
)

// targetRepo lays out one file per validation outcome.
func targetRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range []string{
		"app/src/main/AndroidManifest.xml",
		"app/src/main/res/layout/activity_main.xml",
		"app/src/main/java/com/x/Main.java",
		"app/src/main/java/com/x/Util.kt",
		"app/build/intermediates/merged_manifest/AndroidManifest.xml",
		"app/.cache/Hidden.java",
		"app/build.gradle.kts",
		"app/lint-baseline.xml",
		"app/src/main/assets/config.json",
	} {
		writeSource(t, root, rel, "x\n")
	}
	require.NoError(t, os.Symlink(
		filepath.Join(root, "app/src/main/java/com/x/Main.java"),
		filepath.Join(root, "app/src/main/java/com/x/Link.java")))
	return root
}

func TestValidateTargets_RejectsEachReason(t *testing.T) {
	root := targetRepo(t)
	cases := map[string]string{
		"":                                     reasonInvalidPath,
		"../outside.java":                      reasonInvalidPath,
		"/etc/passwd":                          reasonInvalidPath,
		"app/src/main/java/com/x/Missing.java": reasonInvalidPath,
		"app/src/main/java/com/x":              reasonInvalidPath, // a directory
		"app/src/main/java/com/x/Link.java":    reasonInvalidPath, // a symlink
		"app/build/intermediates/merged_manifest/AndroidManifest.xml": reasonGenerated,
		"app/.cache/Hidden.java":          reasonGenerated,
		"app/build.gradle.kts":            reasonBuildFile,
		"app/lint-baseline.xml":           reasonUnsupported,
		"app/src/main/assets/config.json": reasonUnsupported,
	}
	for path, want := range cases {
		accepted, rejected := validateTargets(root, []agent.Target{{Path: path, Why: "w"}})
		require.Empty(t, accepted, path)
		require.Equal(t, []rejection{{Path: path, Reason: want}}, rejected, path)
	}
}

func TestValidateTargets_AcceptsAndOrdersManifestResSource(t *testing.T) {
	root := targetRepo(t)
	accepted, rejected := validateTargets(root, []agent.Target{
		{Path: "app/src/main/java/com/x/Main.java", Why: "src"},
		{Path: "app/src/main/res/layout/activity_main.xml", Why: "res"},
		{Path: "app/src/main/java/com/x/Util.kt", Why: "kt"},
		{Path: "./app/src/main/AndroidManifest.xml", Why: "manifest"},
	})
	require.Empty(t, rejected)
	require.Equal(t, []agent.Target{
		{Path: "app/src/main/AndroidManifest.xml", Why: "manifest"},
		{Path: "app/src/main/res/layout/activity_main.xml", Why: "res"},
		{Path: "app/src/main/java/com/x/Main.java", Why: "src"},
		{Path: "app/src/main/java/com/x/Util.kt", Why: "kt"},
	}, accepted)
}

// TestValidateTargets_PruneCheckIsCaseInsensitive is F3: agent.PruneDir's own
// component check is exact-case, so a differently-cased build directory
// (seen from a compiled app that does not preserve the checkout's casing)
// slipped the prune check.
func TestValidateTargets_PruneCheckIsCaseInsensitive(t *testing.T) {
	root := targetRepo(t)
	writeSource(t, root, "app/Build/intermediates/AndroidManifest.xml", "x\n")
	accepted, rejected := validateTargets(root, []agent.Target{
		{Path: "app/Build/intermediates/AndroidManifest.xml", Why: "w"},
	})
	require.Empty(t, accepted)
	require.Equal(t, []rejection{{Path: "app/Build/intermediates/AndroidManifest.xml", Reason: reasonGenerated}}, rejected)
}

// TestValidateTargets_PruneCheckFollowsSymlinkedDirectory is F3's other half:
// the check ran on the path the agent sent, not on the path safeDest actually
// resolves, so a symlinked directory that lands inside build/ was never
// caught.
func TestValidateTargets_PruneCheckFollowsSymlinkedDirectory(t *testing.T) {
	root := targetRepo(t)
	writeSource(t, root, "build/generated/AndroidManifest.xml", "x\n")
	require.NoError(t, os.Symlink(
		filepath.Join(root, "build/generated"),
		filepath.Join(root, "app/link")))

	accepted, rejected := validateTargets(root, []agent.Target{
		{Path: "app/link/AndroidManifest.xml", Why: "w"},
	})
	require.Empty(t, accepted)
	require.Equal(t, []rejection{{Path: "app/link/AndroidManifest.xml", Reason: reasonGenerated}}, rejected)
}

func TestValidateTargets_MergesDuplicateWhy(t *testing.T) {
	root := targetRepo(t)
	accepted, rejected := validateTargets(root, []agent.Target{
		{Path: "app/src/main/AndroidManifest.xml", Why: "exported=false on A"},
		{Path: "app/src/main/./AndroidManifest.xml", Why: "exported=false on B"},
	})
	require.Empty(t, rejected)
	require.Equal(t, []agent.Target{{
		Path: "app/src/main/AndroidManifest.xml",
		Why:  "exported=false on A; exported=false on B",
	}}, accepted)
}
