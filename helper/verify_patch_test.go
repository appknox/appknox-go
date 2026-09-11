package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Each test names the repository whose autofix branch failed to compile on
// 2026-09-09 for that reason. They are regressions against real breaks, not
// invented cases.

// writeRepo writes files into a temp checkout and returns its root.
func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o755))
		require.NoError(t, os.WriteFile(abs, []byte(body), 0o644))
	}
	return root
}

func TestVerifyPatchRejectsBuildFile(t *testing.T) {
	// aibom-android: edited app/build.gradle.kts, which SCOPE forbids.
	root := writeRepo(t, map[string]string{"app/build.gradle.kts": "android { }\n"})
	v := verifyPatch(root, "app/build.gradle.kts", "android { buildTypes { } }\n")
	require.NotNil(t, v)
	require.Equal(t, "build-file", v.Rule)
}

func TestVerifyPatchAllowsSourceFile(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/java/A.java": "class A {}\n"})
	require.Nil(t, verifyPatch(root, "app/src/main/java/A.java", "class A { int x; }\n"))
}

func TestVerifyPatchRejectsMalformedXML(t *testing.T) {
	// AndroGoat: the edit emitted </manifest> in the middle of an element.
	root := writeRepo(t, map[string]string{"app/src/main/AndroidManifest.xml": "<manifest/>\n"})
	bad := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:label="x">
</manifest>
  </application>
`
	v := verifyPatch(root, "app/src/main/AndroidManifest.xml", bad)
	require.NotNil(t, v)
	require.Equal(t, "malformed-xml", v.Rule)
}

func TestVerifyPatchAcceptsWellFormedXML(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/AndroidManifest.xml": "<manifest/>\n"})
	good := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:label="x"/>
</manifest>
`
	require.Nil(t, verifyPatch(root, "app/src/main/AndroidManifest.xml", good))
}

func TestVerifyPatchRejectsMissingResource(t *testing.T) {
	// kgb_messenger and playstore-auth: the manifest was pointed at a
	// network_security_config.xml that step 1 was supposed to create, and the
	// fixer cannot create files.
	root := writeRepo(t, map[string]string{"app/src/main/AndroidManifest.xml": "<manifest/>\n"})
	patched := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:networkSecurityConfig="@xml/network_security_config"/>
</manifest>
`
	v := verifyPatch(root, "app/src/main/AndroidManifest.xml", patched)
	require.NotNil(t, v)
	require.Equal(t, "missing-resource", v.Rule)
	require.Contains(t, v.Detail, "@xml/network_security_config")
}

func TestVerifyPatchAcceptsExistingResource(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/src/main/AndroidManifest.xml":                 "<manifest/>\n",
		"app/src/main/res/xml/network_security_config.xml": "<network-security-config/>\n",
	})
	patched := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:networkSecurityConfig="@xml/network_security_config"/>
</manifest>
`
	require.Nil(t, verifyPatch(root, "app/src/main/AndroidManifest.xml", patched))
}

func TestVerifyPatchRejectsGeneratedSymbolImport(t *testing.T) {
	// allsafe-android: imported a BuildConfig not generated for that package.
	root := writeRepo(t, map[string]string{"app/src/main/java/A.java": "class A {}\n"})
	patched := "import infosecadventures.allsafe.BuildConfig;\nclass A {}\n"
	v := verifyPatch(root, "app/src/main/java/A.java", patched)
	require.NotNil(t, v)
	require.Equal(t, "generated-symbol", v.Rule)
}

func TestVerifyPatchRejectsUnresolvedImport(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/java/A.java": "class A {}\n"})
	patched := "import com.example.NoSuchHelper;\nclass A {}\n"
	v := verifyPatch(root, "app/src/main/java/A.java", patched)
	require.NotNil(t, v)
	require.Equal(t, "unresolved-import", v.Rule)
}

func TestVerifyPatchAcceptsPlatformAndLocalImports(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/src/main/java/A.java":          "class A {}\n",
		"app/src/main/java/SessionStore.kt": "class SessionStore\n",
	})
	patched := "import java.security.SecureRandom;\n" +
		"import androidx.core.app.ActivityCompat;\n" +
		"import com.demo.sast.SessionStore;\nclass A {}\n"
	require.Nil(t, verifyPatch(root, "app/src/main/java/A.java", patched))
}

func TestVerifyPatchRejectsManifestMergeConflict(t *testing.T) {
	// Anki-Android and thunderbird: allowBackup changed in one manifest of a
	// merged flavour set.
	root := writeRepo(t, map[string]string{
		"app/src/main/AndroidManifest.xml": "<manifest/>\n",
		"app/src/amazon/AndroidManifest.xml": `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="true"/>
</manifest>
`,
	})
	patched := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false"/>
</manifest>
`
	v := verifyPatch(root, "app/src/main/AndroidManifest.xml", patched)
	require.NotNil(t, v)
	require.Equal(t, "manifest-merge-conflict", v.Rule)
	require.Contains(t, v.Detail, "app/src/amazon/AndroidManifest.xml")
}

func TestVerifyPatchAllowsSoleManifest(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/AndroidManifest.xml": "<manifest/>\n"})
	patched := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false"/>
</manifest>
`
	require.Nil(t, verifyPatch(root, "app/src/main/AndroidManifest.xml", patched))
}

// The attribute the fixer changed is not the one the sibling sets, so there is
// no merge conflict and the patch stands.
func TestVerifyPatchIgnoresUnrelatedSiblingAttribute(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/src/main/AndroidManifest.xml": "<manifest/>\n",
		"app/src/amazon/AndroidManifest.xml": `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:launchMode="standard"/>
</manifest>
`,
	})
	patched := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false"/>
</manifest>
`
	require.Nil(t, verifyPatch(root, "app/src/main/AndroidManifest.xml", patched))
}
