package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// mfva 17 (Application Logs): KnoxIQ's remediation strips android.util.Log in
// release with an -assumenosideeffects rule in app/proguard-rules.pro. The file
// exists (comments only), but was out of bounds, so 17 reported FIXED from its
// build.gradle half while the log calls stayed.
const mfvaRules = `# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in /usr/local/Cellar/android-sdk/24.3.3/tools/proguard/proguard-android.txt
`

const logStrip = `-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
}
`

func rulesRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app/build.gradle"), []byte("android {}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app/proguard-rules.pro"), []byte(mfvaRules), 0o644))
	return root
}

func TestEditableRulesFile(t *testing.T) {
	root := rulesRepo(t)
	require.True(t, editableRulesFile(root, "app/proguard-rules.pro"))
	require.False(t, editableRulesFile(root, "proguard-rules.pro"), "root rules file stays out")

	// No module build script beside it: not a module's rules file.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "lib/proguard-rules.pro"), nil, 0o644))
	require.False(t, editableRulesFile(root, "lib/proguard-rules.pro"))

	// The root of a nested Gradle project (android/ with settings.gradle) is not a module.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "android"), 0o755))
	for _, f := range []string{"build.gradle", "settings.gradle", "proguard-rules.pro"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, "android", f), nil, 0o644))
	}
	require.False(t, editableRulesFile(root, "android/proguard-rules.pro"))
}

func TestCheckTargetAcceptsModuleRulesFile(t *testing.T) {
	root := rulesRepo(t)
	rel, reason := checkTarget(root, "app/proguard-rules.pro")
	require.Empty(t, reason)
	require.Equal(t, "app/proguard-rules.pro", rel)
}

func TestVerifyPatchAcceptsAddedLogStripRule(t *testing.T) {
	root := rulesRepo(t)
	require.Nil(t, verifyPatch(root, "app/proguard-rules.pro", mfvaRules, mfvaRules+"\n"+logStrip))
}

func TestVerifyPatchAcceptsDontwarnAndKeep(t *testing.T) {
	root := rulesRepo(t)
	add := "-dontwarn okhttp3.**\n-dontwarn okio.**\n-keep class com.appknox.mfva.** { *; }\n-keepattributes Signature\n"
	require.Nil(t, verifyPatch(root, "app/proguard-rules.pro", mfvaRules, mfvaRules+add))
}

func TestVerifyPatchRefusesRulesFileRemovalOrRewrite(t *testing.T) {
	root := rulesRepo(t)
	orig := mfvaRules + "-keep class com.appknox.mfva.MainActivity\n"

	v := verifyPatch(root, "app/proguard-rules.pro", orig, mfvaRules)
	require.NotNil(t, v)
	require.Equal(t, "rules-file-removal", v.Rule)

	v = verifyPatch(root, "app/proguard-rules.pro", orig, mfvaRules+"-keep class com.appknox.mfva.Other\n")
	require.NotNil(t, v, "changing an existing rule is a removal plus an addition")
	require.Equal(t, "rules-file-removal", v.Rule)

	// Deleting comments is not a rule change.
	require.Nil(t, verifyPatch(root, "app/proguard-rules.pro", orig, "-keep class com.appknox.mfva.MainActivity\n"))
}

func TestVerifyPatchRefusesUnlistedDirectives(t *testing.T) {
	root := rulesRepo(t)
	for _, add := range []string{
		"-include /etc/other.pro\n",
		"-dontobfuscate\n",
		"-dontshrink\n",
		"-printconfiguration /tmp/out.txt\n",
		"-dontwarn okhttp3.** -include ../secret.pro\n", // several options on one line
		"-injars in.jar\n",
		"@other.pro\n", // ProGuard's shorthand for -include
	} {
		v := verifyPatch(root, "app/proguard-rules.pro", mfvaRules, mfvaRules+add)
		require.NotNil(t, v, add)
		require.Equal(t, "rules-file-directive", v.Rule, add)
	}
}

func TestVerifyPatchRefusesUnbalancedRulesBlock(t *testing.T) {
	root := rulesRepo(t)
	v := verifyPatch(root, "app/proguard-rules.pro", mfvaRules, mfvaRules+"-assumenosideeffects class android.util.Log {\n")
	require.NotNil(t, v)
}

func TestRulesFileRanksWithBuildScripts(t *testing.T) {
	require.Equal(t, 3, targetRank("app/proguard-rules.pro"))
	require.True(t, supportedTarget("app/proguard-rules.pro"))
}

// A patched rules file whose finding then fails elsewhere is rolled back like
// a patched build script: half a release-config change is not a fix.
func TestNeedsRollbackOnPatchedRulesFile(t *testing.T) {
	require.True(t, needsRollback([]targetResult{
		{Path: "app/proguard-rules.pro", Patched: true},
		{Path: "app/build.gradle", Reason: "rejected by patch gate: build-script-addition"},
	}))
}

// Review bypasses: each form below reached a release rules file past the gate
// before the tokenizer was tightened. ProGuard reads quoted words whole,
// treats a bare CR as a line end and } as a word delimiter, accepts Java
// whitespace Go's \s does not, and reads @file anywhere outside a class spec.
func TestVerifyPatchRefusesRulesGateBypasses(t *testing.T) {
	root := rulesRepo(t)
	for name, add := range map[string]string{
		"hash inside quotes":   "-dontwarn \"a#b\" -include /tmp/evil.pro\n",
		"bare CR":              "# note\r-include evil.pro\r-dontobfuscate\n",
		"glued to brace":       "-keep class B { *; }-include evil.pro\n",
		"vertical tab":         "-dontwarn x\v-dontobfuscate\n",
		"em space":             "-dontwarn x\u2003-dontobfuscate\n",
		"at mid-line":          "-keep class B { *; } @evil.pro\n",
		"quoted braces":        "-dontwarn '{'\n@evil.pro\n-dontwarn '}'\n",
		"negative depth":       "-dontwarn '}'\n@evil.pro\n-dontwarn '{'\n",
		"closing brace first":  "}\n@evil.pro\n{\n",
		"strip everything":     "-assumenosideeffects class * { *; }\n",
		"strip security class": "-assumenosideeffects class com.appknox.mfva.HookingDetector { *; }\n",
		"dontwarn everything":  "-dontwarn **\n",
		"dontwarn bare":        "-dontwarn\n",
		"keep everything":      "-keep class ** { *; }\n",
	} {
		require.NotNil(t, verifyPatch(root, "app/proguard-rules.pro", mfvaRules, mfvaRules+add), name)
	}
}

// What the tightening must still let through: annotations in a member spec,
// Parcelable-style wildcards, and the standard Log/PrintStream strip.
func TestVerifyPatchKeepsCommonRules(t *testing.T) {
	root := rulesRepo(t)
	for _, add := range []string{
		"-keepclassmembers class * {\n    @android.webkit.JavascriptInterface <methods>;\n}\n",
		"-keep class * implements android.os.Parcelable {\n    public static final ** CREATOR;\n}\n",
		"-assumenosideeffects class java.io.PrintStream {\n    public void println(...);\n}\n",
		"-keepattributes *Annotation*, Signature\n",
		"-dontwarn okhttp3.**\r\n-dontwarn okio.**\r\n",
	} {
		require.Nil(t, verifyPatch(root, "app/proguard-rules.pro", mfvaRules, mfvaRules+add), add)
	}
}

// Re-review: wildcard spellings the keep-all/dontwarn-all patterns missed.
// Every keep or dontwarn rule must name a real package or class somewhere
// that narrows it (the filter, extends/implements, or an annotation).
func TestVerifyPatchRefusesWildcardSpellings(t *testing.T) {
	root := rulesRepo(t)
	for _, add := range []string{
		"-keep class ***\n",
		"-keep public class **\n",
		"-keep,allowshrinking class **\n",
		"-keep class **.*\n",
		"-keepclasseswithmembers class * { *; }\n",
		"-keepclassmembers class ** { *; }\n",
		"-keepclassmembers class * {\n    *;\n}\n",
		"-keep class ** { java.lang.String x; }\n",
		"-dontwarn ***\n",
		"-dontwarn *.**\n",
		"-dontwarn com.x {\n@evil.pro\n-dontwarn com.y }\n",
	} {
		require.NotNil(t, verifyPatch(root, "app/proguard-rules.pro", mfvaRules, mfvaRules+add), add)
	}
}

func TestVerifyPatchKeepsAnnotatedAndSpecificRules(t *testing.T) {
	root := rulesRepo(t)
	for _, add := range []string{
		"-keep @androidx.annotation.Keep class * { *; }\n",
		"-keepclassmembers class * { @android.webkit.JavascriptInterface <methods>; }\n",
		"-keepclassmembers class * {\n    @com.google.gson.annotations.SerializedName <fields>;\n}\n",
		"-keep class com.appknox.mfva.MainActivity\n",
		"-keepnames class * extends android.app.Activity\n",
	} {
		require.Nil(t, verifyPatch(root, "app/proguard-rules.pro", mfvaRules, mfvaRules+add), add)
	}
}

// Round-3: keep-everything rules that still named a dotted class.
func TestVerifyPatchRefusesNegatedAndObjectRules(t *testing.T) {
	root := rulesRepo(t)
	for _, add := range []string{
		"-keep class !com.a.B { *; }\n",
		"-dontwarn !com.a.B\n",
		"-keep class * extends java.lang.Object { *; }\n",
		"-dontwarn com.a.B -keepclassmembers class * {\n*;\n}\n",
		"-keep class com.a.B { *; } -keepclassmembers class * {\n*;\n}\n",
	} {
		require.NotNil(t, verifyPatch(root, "app/proguard-rules.pro", mfvaRules, mfvaRules+add), add)
	}
	// A negation beside a positive name is an ordinary exclusion.
	require.Nil(t, verifyPatch(root, "app/proguard-rules.pro", mfvaRules,
		mfvaRules+"-dontwarn okhttp3.**, !okhttp3.internal.Util\n"))
}
