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

// agp8NoBuildConfig is AndroGoat's shape: AGP 8, viewBinding on, buildConfig
// never enabled -- so the class is never generated.
func agp8NoBuildConfig() map[string]string {
	return map[string]string{
		"build.gradle":     "buildscript {\n dependencies {\n  classpath 'com.android.tools.build:gradle:8.13.1'\n }\n}\n",
		"app/build.gradle": "android {\n compileSdkVersion 34\n buildFeatures {\n  viewBinding true\n }\n}\n",
	}
}

// AndroGoat, 2026-09-16: once the brace break was fixed, the next run wrote
// `if (BuildConfig.DEBUG)` into a file in the module's own package -- no import,
// so the import rule never saw it -- and kotlinc answered "Unresolved
// reference: BuildConfig".
func TestVerifyPatchRejectsBareBuildConfigWhenNotGenerated(t *testing.T) {
	root := writeRepo(t, agp8NoBuildConfig())
	original := "package a\n\nclass A {\n    fun f() {\n    }\n}\n"
	patched := "package a\n\nclass A {\n    fun f() {\n        if (BuildConfig.DEBUG) { log() }\n    }\n}\n"

	v := verifyPatch(root, "app/src/main/java/a/A.kt", original, patched)

	require.NotNil(t, v)
	require.Equal(t, "buildconfig-not-generated", v.Rule)
}

// The same reference is perfectly legal once a module asks for the class.
func TestVerifyPatchAcceptsBuildConfigWhenEnabled(t *testing.T) {
	files := agp8NoBuildConfig()
	files["app/build.gradle"] = "android {\n compileSdkVersion 34\n buildFeatures {\n  buildConfig true\n }\n}\n"
	root := writeRepo(t, files)
	original := "package a\n\nclass A {\n    fun f() {\n    }\n}\n"
	patched := "package a\n\nclass A {\n    fun f() {\n        if (BuildConfig.DEBUG) { log() }\n    }\n}\n"

	require.Nil(t, verifyPatch(root, "app/src/main/java/a/A.kt", original, patched))
}

// AGP 7 generates BuildConfig by default, so the same patch must pass there.
// Abstaining is the whole point: the gate must not punish an older project.
func TestVerifyPatchAbstainsOnBuildConfigForAGP7(t *testing.T) {
	files := agp8NoBuildConfig()
	files["build.gradle"] = "buildscript {\n dependencies {\n  classpath 'com.android.tools.build:gradle:7.4.2'\n }\n}\n"
	root := writeRepo(t, files)
	original := "package a\n\nclass A {\n    fun f() {\n    }\n}\n"
	patched := "package a\n\nclass A {\n    fun f() {\n        if (BuildConfig.DEBUG) { log() }\n    }\n}\n"

	require.Nil(t, verifyPatch(root, "app/src/main/java/a/A.kt", original, patched))
}

// Rule 1: a BuildConfig reference the repository already had is not the
// fixer's to answer for.
func TestVerifyPatchIgnoresPreExistingBuildConfigUsage(t *testing.T) {
	root := writeRepo(t, agp8NoBuildConfig())
	original := "package a\n\nclass A {\n    val d = BuildConfig.DEBUG\n}\n"
	patched := original + "\n// touched elsewhere\n"

	require.Nil(t, verifyPatch(root, "app/src/main/java/a/A.kt", original, patched))
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

// AndroGoat appended a duplicated tail past the class's final brace, and
// kotlinc answered with eleven "Expecting a top level declaration" errors.
func TestVerifyPatchRejectsTrailingBraces(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/java/A.kt": "class A {\n}\n"})
	original := "class A {\n    fun f() {\n        return\n    }\n}\n"
	patched := original + "String(\"\") { \"%02x\".format(it) }\n        return md\n    }\n}\n"
	v := verifyPatch(root, "app/src/main/java/A.kt", original, patched)
	require.NotNil(t, v)
	require.Equal(t, "unbalanced-braces", v.Rule)
	require.Contains(t, v.Detail, "extra '}'")
}

func TestVerifyPatchRejectsDroppedClosingBrace(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/java/A.java": "class A {}\n"})
	original := "class A {\n    void f() {\n    }\n}\n"
	patched := "class A {\n    void f() {\n        if (x) {\n    }\n}\n"
	v := verifyPatch(root, "app/src/main/java/A.java", original, patched)
	require.NotNil(t, v)
	require.Equal(t, "unbalanced-braces", v.Rule)
	require.Contains(t, v.Detail, "unclosed '{'")
}

// A brace inside a string, a char literal, a comment or a Kotlin raw string is
// text, not structure. Counting it would reject correct code.
func TestVerifyPatchIgnoresBracesInLiteralsAndComments(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/java/A.kt": "class A {}\n"})
	original := "class A {\n}\n"
	patched := "class A {\n" +
		"    val s = \"a { b\"\n" +
		"    val c = '{'\n" +
		"    // a stray } in a comment\n" +
		"    /* and { another */\n" +
		"    val raw = \"\"\"unclosed { in a raw string\"\"\"\n" +
		"}\n"
	require.Nil(t, verifyPatch(root, "app/src/main/java/A.kt", original, patched))
}

// When the scanner cannot even balance the ORIGINAL, it does not understand the
// file and must not judge the patch.
func TestVerifyPatchAbstainsWhenOriginalIsUnbalanced(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/java/A.kt": "x\n"})
	original := "class A {\n"             // already unbalanced to this scanner
	patched := "class A {\n  val x = 1\n" // still unbalanced; not our business
	require.Nil(t, verifyPatch(root, "app/src/main/java/A.kt", original, patched))
}

// Brace counting applies to code, not to every file that happens to have braces.
func TestVerifyPatchSkipsBraceCheckForNonSource(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/res/raw/data.json": "{}\n"})
	require.Nil(t, verifyPatch(root, "app/src/main/res/raw/data.json", "{}\n", "{ \"a\": 1\n"))
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

// aibom-android runs 35820530274 and 35825717963: CI builds the app BEFORE
// autofix in the same job, so Gradle's merged copy of the manifest sits under
// app/build/intermediates still saying allowBackup="true". That is build
// output, not a flavour manifest in the merge -- the correct fix to the source
// manifest must stand, and the fixer must not be told to abandon it.
func TestVerifyPatchIgnoresBuildOutputManifests(t *testing.T) {
	buildCopy := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="true"/>
</manifest>
`
	root := writeRepo(t, map[string]string{
		"app/src/main/AndroidManifest.xml": "<manifest/>\n",
		"app/build/intermediates/bundle_manifest/debug/processApplicationManifestDebugForBundle/AndroidManifest.xml": buildCopy,
		"app/.gradle/cache/AndroidManifest.xml": buildCopy,
	})
	patched := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false"/>
</manifest>
`
	require.Nil(t, verifyPatch(root, "app/src/main/AndroidManifest.xml", "<manifest/>\n", patched))
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
