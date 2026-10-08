package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Keylogger Protection (133), as dvfa, PeopleInSpace and vuln-bank-mobile
// received it: an input method service, its config XML and a manifest entry.
const (
	imeGradle    = "android {\n    namespace 'com.x'\n}\n"
	imeClassRel  = "app/src/main/java/com/x/SecureIME.java"
	imeClass     = "package com.x;\n\npublic class SecureIME {}\n"
	imeConfigRel = "app/src/main/res/xml/input_method_config.xml"
	imeConfigRef = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
		"<input-method xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
		"    android:label=\"@string/secure_keyboard_name\" />\n"
	imeConfigLit = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
		"<input-method xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
		"    android:label=\"Secure keyboard\" />\n"
	stringsRel  = "app/src/main/res/values/strings.xml"
	stringsBody = "<resources>\n    <string name=\"app_name\">x</string>\n</resources>\n"
	stringsDone = "<resources>\n    <string name=\"app_name\">x</string>\n" +
		"    <string name=\"secure_keyboard_name\">Secure keyboard</string>\n</resources>\n"
	imeService = "    <service android:name=\".SecureIME\" android:exported=\"true\"" +
		" android:permission=\"android.permission.BIND_INPUT_METHOD\">\n" +
		"      <intent-filter><action android:name=\"android.view.InputMethod\" /></intent-filter>\n"
	manifestSvc = "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"  <application android:label=\"mfva\">\n" + imeService + "    </service>\n  </application>\n</manifest>\n"
	manifestIME = "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"  <application android:label=\"mfva\">\n" + imeService +
		"      <meta-data android:name=\"android.view.im\" android:resource=\"@xml/input_method_config\" />\n" +
		"    </service>\n  </application>\n</manifest>\n"
)

func imeRepo(t *testing.T, extra map[string]string) string {
	t.Helper()
	files := map[string]string{"app/build.gradle": imeGradle, manifestRel: manifestBody, stringsRel: stringsBody}
	for k, v := range extra {
		files[k] = v
	}
	return writeRepo(t, files)
}

// outcomePatchPaths lists the paths of an Outcome's patches. Named apart from
// the pre-existing patchPaths(patches []filePatch) string in autofix.go
// (joins for display) -- same name, different signature, so it cannot be
// reused here; this is the brief's helper of the same name, renamed to avoid
// the collision.
func outcomePatchPaths(out Outcome) []string {
	paths := []string{}
	for _, p := range out.Patches {
		paths = append(paths, p.Path)
	}
	return paths
}

func TestUnresolvedUnitRefs(t *testing.T) {
	kt := "app/src/main/java/com/x/K.kt"
	root := imeRepo(t, map[string]string{
		imeConfigRel: imeConfigRef,
		manifestRel:  manifestIME,
		kt: "package com.x\n\nclass K { val a = R.layout.gone; val b = android.R.layout.simple_list_item_1; " +
			"val c = R.string.app_name }\n",
	})
	before := map[string]string{manifestRel: manifestBody, kt: "package com.x\n\nclass K\n"}
	got := unresolvedUnitRefs(root, []string{imeConfigRel, manifestRel, kt}, before)
	require.Equal(t, []unresolvedRef{
		{Kind: "string", Name: "secure_keyboard_name", From: imeConfigRel},
		{Kind: "class", Name: "com.x.SecureIME", From: manifestRel},
		{Kind: "layout", Name: "gone", From: kt},
	}, got)
	require.Equal(t, "@string/secure_keyboard_name", got[0].String())
	require.Equal(t, "R.layout.gone", got[2].String())
}
