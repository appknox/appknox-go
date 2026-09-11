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
	v := verifyPatch(root, "app/build.gradle.kts", "android { }\n", "android { buildTypes { } }\n")
	require.NotNil(t, v)
	require.Equal(t, "build-file", v.Rule)
}

func TestVerifyPatchAllowsSourceFile(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/java/A.java": "class A {}\n"})
	require.Nil(t, verifyPatch(root, "app/src/main/java/A.java", "class A {}\n", "class A { int x; }\n"))
}

func TestVerifyPatchRejectsMalformedXML(t *testing.T) {
	// AndroGoat: the edit emitted </manifest> in the middle of an element.
	root := writeRepo(t, map[string]string{"app/src/main/AndroidManifest.xml": "<manifest/>\n"})
	bad := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:label="x">
</manifest>
  </application>
`
	v := verifyPatch(root, "app/src/main/AndroidManifest.xml", "<manifest/>\n", bad)
	require.NotNil(t, v)
	require.Equal(t, "malformed-xml", v.Rule)
}

func TestVerifyPatchAcceptsWellFormedXML(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/AndroidManifest.xml": "<manifest/>\n"})
	good := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:label="x"/>
</manifest>
`
	require.Nil(t, verifyPatch(root, "app/src/main/AndroidManifest.xml", "<manifest/>\n", good))
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
	v := verifyPatch(root, "app/src/main/AndroidManifest.xml", "<manifest/>\n", patched)
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
	require.Nil(t, verifyPatch(root, "app/src/main/AndroidManifest.xml", "<manifest/>\n", patched))
}

func TestVerifyPatchRejectsGeneratedSymbolImport(t *testing.T) {
	// allsafe-android: imported a BuildConfig not generated for that package.
	root := writeRepo(t, map[string]string{"app/src/main/java/A.java": "class A {}\n"})
	patched := "import infosecadventures.allsafe.BuildConfig;\nclass A {}\n"
	v := verifyPatch(root, "app/src/main/java/A.java", "class A {}\n", patched)
	require.NotNil(t, v)
	require.Equal(t, "generated-symbol", v.Rule)
}

// Imports that resolve through the Gradle dependency graph are NOT on disk, so
// their absence proves nothing. Rejecting these cost Anki-Android, NewPipe,
// BrokenSSLApp and ovaa valid fixes on 2026-09-11; only BuildConfig is judged.
func TestVerifyPatchAcceptsDependencyImports(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/java/A.java": "class A {}\n"})
	patched := "import timber.log.Timber;\n" +
		"import org.apache.http.conn.ssl.SSLSocketFactory;\n" +
		"import com.ichi2.anki.CollectionManager.TR;\n" +
		"import com.ichi2.anki.R;\n" +
		"import java.security.SecureRandom;\nclass A {}\n"
	require.Nil(t, verifyPatch(root, "app/src/main/java/A.java", "class A {}\n", patched))
}

// Fossify Calendar lost all 10 fixes to a drawable that was real and sitting in
// res/drawable-nodpi, which a bare res/drawable match misses.
func TestVerifyPatchAcceptsQualifiedResourceDir(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/src/main/AndroidManifest.xml":                       "<manifest/>\n",
		"app/src/main/res/drawable-nodpi/img_widget_preview.png": "png",
		"app/src/main/res/values-night/colors.xml":               "<resources/>\n",
	})
	patched := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:banner="@drawable/img_widget_preview"/>
</manifest>
`
	require.Nil(t, verifyPatch(root, "app/src/main/AndroidManifest.xml", "<manifest/>\n", patched))
}

// A reference the patch did not introduce is the repository's, not the fixer's.
// Judging the whole file is what killed Calendar: its manifest already named a
// resource, and every fix to that file was blamed for it.
func TestVerifyPatchIgnoresPreExistingReferences(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/AndroidManifest.xml": "<manifest/>\n"})
	original := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:banner="@drawable/absent_from_this_checkout"/>
</manifest>
`
	patched := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:banner="@drawable/absent_from_this_checkout" android:allowBackup="false"/>
</manifest>
`
	require.Nil(t, verifyPatch(root, "app/src/main/AndroidManifest.xml", original, patched))
}

// A pre-existing BuildConfig import is likewise not the fixer's doing.
func TestVerifyPatchIgnoresPreExistingBuildConfigImport(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/java/A.java": "class A {}\n"})
	original := "import com.example.BuildConfig;\nclass A {}\n"
	patched := "import com.example.BuildConfig;\nclass A { int x; }\n"
	require.Nil(t, verifyPatch(root, "app/src/main/java/A.java", original, patched))
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
	v := verifyPatch(root, "app/src/main/AndroidManifest.xml", "<manifest/>\n", patched)
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
	require.Nil(t, verifyPatch(root, "app/src/main/AndroidManifest.xml", "<manifest/>\n", patched))
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
	require.Nil(t, verifyPatch(root, "app/src/main/AndroidManifest.xml", "<manifest/>\n", patched))
}
