package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Damn-Vulnerable-React-Native holds three separate Gradle builds
// (variant-a/b/c). Completion defined secure_keyboard_subtype_label in
// variant-a's strings.xml only; the repo-wide index then called variant-b's
// reference resolved and AAPT failed: "resource string/... not found".
func threeVariantRepo() map[string]string {
	files := map[string]string{}
	for _, v := range []string{"variant-a", "variant-b"} {
		files[v+"/android/settings.gradle"] = "include ':app'\n"
		files[v+"/android/app/build.gradle"] = "android { namespace 'com.dvrn.app' }\n"
		files[v+"/android/app/src/main/res/values/strings.xml"] = "<resources>\n  <string name=\"app_name\">X</string>\n</resources>\n"
	}
	files["variant-a/android/app/src/main/res/values/strings.xml"] =
		"<resources>\n  <string name=\"app_name\">X</string>\n  <string name=\"only_in_a\">A</string>\n</resources>\n"
	files["variant-a/android/app/src/main/java/com/dvrn/app/OnlyA.kt"] = "package com.dvrn.app\n\nclass OnlyA\n"
	files["shared/res/values/strings.xml"] = "<resources>\n  <string name=\"loose\">L</string>\n</resources>\n"
	return files
}

func TestResourceIndexScopedToGradleBuild(t *testing.T) {
	root := writeRepo(t, threeVariantRepo())
	x := buildResourceIndex(root)
	a := "variant-a/android/app/src/main/res/xml/c.xml"
	b := "variant-b/android/app/src/main/res/xml/c.xml"

	require.True(t, x.hasFrom(a, "string", "only_in_a"))
	require.False(t, x.hasFrom(b, "string", "only_in_a"), "another Gradle build's resource is not visible")
	require.True(t, x.hasFrom(b, "string", "app_name"))
	require.True(t, x.hasFrom(b, "string", "loose"), "a resource outside any Gradle build stays visible")
	require.True(t, x.hasFrom("tools/x.xml", "string", "only_in_a"), "a file outside any build sees everything")
	require.True(t, x.hasFrom(b, "integer", "google_play_services_version"))

	require.True(t, x.hasClassFrom(a, "com.dvrn.app.OnlyA"))
	require.False(t, x.hasClassFrom(b, "com.dvrn.app.OnlyA"))
}

func TestVerifyPatchMissingResourceAcrossBuilds(t *testing.T) {
	root := writeRepo(t, threeVariantRepo())
	p := "variant-b/android/app/src/main/res/xml/input_method_config.xml"
	patched := "<input-method xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"  <subtype android:label=\"@string/only_in_a\"/>\n</input-method>\n"
	v := verifyPatch(root, p, "", patched)
	require.NotNil(t, v)
	require.Equal(t, "missing-resource", v.Rule)
}

// The resolve pass must report the reference once PER BUILD, so each variant's
// completion defines it in its own strings.xml.
func TestUnresolvedUnitRefsPerBuild(t *testing.T) {
	files := threeVariantRepo()
	ref := "<input-method xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"  <subtype android:label=\"@string/subtype_label\"/>\n</input-method>\n"
	pa := "variant-a/android/app/src/main/res/xml/input_method_config.xml"
	pb := "variant-b/android/app/src/main/res/xml/input_method_config.xml"
	files[pa], files[pb] = ref, ref
	root := writeRepo(t, files)

	got := unresolvedUnitRefs(root, []string{pa, pb}, map[string]string{})
	require.Len(t, got, 2)
	require.ElementsMatch(t, []string{pa, pb}, []string{got[0].From, got[1].From})
}
