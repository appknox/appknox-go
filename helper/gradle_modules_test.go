package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestModuleRootAndNamespace(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"build.gradle":         "// root project\n",
		"app/build.gradle.kts": "android {\n    namespace = \"com.x.app\"\n}\n",
		"lib/build.gradle":     "android {\n    namespace 'com.x.lib'\n}\n",
		"old/build.gradle":     "android {}\n",
		"old/src/main/AndroidManifest.xml": "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
			"    package=\"com.x.old\">\n</manifest>\n",
		"bare/AndroidManifest.xml": "<manifest/>\n",
	})
	require.Equal(t, "app", moduleRoot(root, "app/src/main/AndroidManifest.xml"))
	require.Equal(t, "lib", moduleRoot(root, "lib/src/debug/res/values/strings.xml"))
	require.Equal(t, ".", moduleRoot(root, "bare/AndroidManifest.xml"), "the root script is the nearest")
	require.Equal(t, "com.x.app", moduleNamespace(root, "app"))
	require.Equal(t, "com.x.lib", moduleNamespace(root, "lib"))
	require.Equal(t, "com.x.old", moduleNamespace(root, "old"), "manifest package= fallback")
	require.Equal(t, "", moduleNamespace(root, ""))

	noGradle := writeRepo(t, map[string]string{"x/AndroidManifest.xml": "<manifest/>\n"})
	require.Equal(t, "", moduleRoot(noGradle, "x/AndroidManifest.xml"))
}

func TestProjectDeps(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"settings.gradle": "include ':app', ':lib', ':core'\n" +
			"project(':core').projectDir = new File(rootDir, 'libs/core')\n",
		"app/build.gradle": "dependencies {\n    implementation project(':lib')\n" +
			"    api project(path: ':core')\n}\n",
		"lib/build.gradle":       "android {}\n",
		"libs/core/build.gradle": "android {}\n",
	})
	require.Equal(t, map[string]bool{"lib": true, "libs/core": true}, projectDeps(root, "app"))
	require.Empty(t, projectDeps(root, "lib"))
}

func TestVerifyPatchMergeScoping(t *testing.T) {
	sets := "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"  <application android:allowBackup=\"true\"/>\n</manifest>\n"
	patched := "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"  <application android:allowBackup=\"false\"/>\n</manifest>\n"
	cases := []struct {
		name     string
		files    map[string]string
		path     string
		conflict bool
	}{
		{"sibling sample modules (ndk-samples)", map[string]string{
			"hello-jni/app/build.gradle": "", "hello-jni/app/src/main/AndroidManifest.xml": "<manifest/>\n",
			"teapots/app/build.gradle": "", "teapots/app/src/main/AndroidManifest.xml": sets,
		}, "hello-jni/app/src/main/AndroidManifest.xml", false},
		{"main and debug of one module (PeopleInSpace)", map[string]string{
			"app/build.gradle": "", "app/src/main/AndroidManifest.xml": "<manifest/>\n",
			"app/src/debug/AndroidManifest.xml": sets,
		}, "app/src/main/AndroidManifest.xml", true},
		{"app and its project(':lib')", map[string]string{
			"settings.gradle":                  "include ':app', ':lib'\n",
			"app/build.gradle":                 "dependencies {\n    implementation project(':lib')\n}\n",
			"app/src/main/AndroidManifest.xml": "<manifest/>\n",
			"lib/build.gradle":                 "", "lib/src/main/AndroidManifest.xml": sets,
		}, "app/src/main/AndroidManifest.xml", true},
		{"type-safe accessor projects.core (Kotlin DSL)", map[string]string{
			"settings.gradle.kts":              "include(\":app\", \":core\")\n",
			"app/build.gradle.kts":             "dependencies {\n    implementation(projects.core)\n}\n",
			"app/src/main/AndroidManifest.xml": "<manifest/>\n",
			"core/build.gradle.kts":            "", "core/src/main/AndroidManifest.xml": sets,
		}, "app/src/main/AndroidManifest.xml", true},
		{"camel-cased accessor projects.featureLogin", map[string]string{
			"settings.gradle.kts":              "include(\":app\")\ninclude(\":feature-login\")\n",
			"app/build.gradle.kts":             "dependencies {\n    implementation(projects.featureLogin)\n}\n",
			"app/src/main/AndroidManifest.xml": "<manifest/>\n",
			"feature-login/build.gradle.kts":   "", "feature-login/src/main/AndroidManifest.xml": sets,
		}, "app/src/main/AndroidManifest.xml", true},
		{"nested accessor projects.feature.login", map[string]string{
			"settings.gradle.kts":              "include(\":app\", \":feature:login\")\n",
			"app/build.gradle.kts":             "dependencies {\n    implementation(projects.feature.login)\n}\n",
			"app/src/main/AndroidManifest.xml": "<manifest/>\n",
			"feature/login/build.gradle.kts":   "", "feature/login/src/main/AndroidManifest.xml": sets,
		}, "app/src/main/AndroidManifest.xml", true},
		{"transitive app -> :feature -> :core", map[string]string{
			"settings.gradle":                  "include ':app', ':feature', ':core'\n",
			"app/build.gradle":                 "dependencies {\n    implementation project(':feature')\n}\n",
			"app/src/main/AndroidManifest.xml": "<manifest/>\n",
			"feature/build.gradle":             "dependencies {\n    api project(':core')\n}\n",
			"core/build.gradle":                "", "core/src/main/AndroidManifest.xml": sets,
		}, "app/src/main/AndroidManifest.xml", true},
		{"transitive through an accessor", map[string]string{
			"settings.gradle.kts":              "include(\":app\", \":feature\", \":core\")\n",
			"app/build.gradle.kts":             "dependencies {\n    implementation(projects.feature)\n}\n",
			"app/src/main/AndroidManifest.xml": "<manifest/>\n",
			"feature/build.gradle.kts":         "dependencies {\n    implementation(projects.core)\n}\n",
			"core/build.gradle.kts":            "", "core/src/main/AndroidManifest.xml": sets,
		}, "app/src/main/AndroidManifest.xml", true},
		{"unresolvable accessor stays repository-wide", map[string]string{
			"settings.gradle.kts":              "include(\":app\", \":wear\")\n",
			"app/build.gradle.kts":             "dependencies {\n    implementation(projects.ghost)\n}\n",
			"app/src/main/AndroidManifest.xml": "<manifest/>\n",
			"wear/build.gradle.kts":            "", "wear/src/main/AndroidManifest.xml": sets,
		}, "app/src/main/AndroidManifest.xml", true},
		{"resolved accessors to other modules do not widen", map[string]string{
			"settings.gradle.kts":              "include(\":app\", \":core\", \":wear\")\n",
			"app/build.gradle.kts":             "dependencies {\n    implementation(projects.core)\n}\n",
			"app/src/main/AndroidManifest.xml": "<manifest/>\n",
			"core/build.gradle.kts":            "",
			"wear/build.gradle.kts":            "", "wear/src/main/AndroidManifest.xml": sets,
		}, "app/src/main/AndroidManifest.xml", false},
		{"unrelated module", map[string]string{
			"app/build.gradle": "", "app/src/main/AndroidManifest.xml": "<manifest/>\n",
			"wear/build.gradle": "", "wear/src/main/AndroidManifest.xml": sets,
		}, "app/src/main/AndroidManifest.xml", false},
		{"non-Gradle tree stays repository-wide", map[string]string{
			"app/src/main/AndroidManifest.xml": "<manifest/>\n", "samples/x/AndroidManifest.xml": sets,
		}, "app/src/main/AndroidManifest.xml", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := writeRepo(t, c.files)
			v := verifyPatch(root, c.path, "<manifest/>\n", patched)
			if !c.conflict {
				require.Nil(t, v)
				return
			}
			require.NotNil(t, v)
			require.Equal(t, "manifest-merge-conflict", v.Rule)
		})
	}
}
