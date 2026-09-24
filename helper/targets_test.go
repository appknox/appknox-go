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
