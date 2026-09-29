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
