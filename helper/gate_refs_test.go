package helper

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	imeConfigRel  = "app/src/main/res/xml/input_method_config.xml"
	imeServiceRel = "app/src/main/java/com/appknox/mfva/SecureInputMethodService.java"
	stringsRel    = "app/src/main/res/values/strings.xml"
	stringsXML    = "<resources>\n    <string name=\"app_name\">mfva</string>\n" +
		"    <item type=\"string\" name=\"ime_label\">Keyboard</item>\n</resources>\n"
)

func imeConfig(ref string) string {
	return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
		"<input-method xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"    <subtype android:name=\"" + ref + "\" android:imeSubtypeMode=\"text\" />\n</input-method>\n"
}

// mfva PR #43: the new IME config referenced a string nothing declared.
func TestVerifyPatch_RefusesAnUndeclaredStringResource(t *testing.T) {
	root := writeRepo(t, map[string]string{stringsRel: stringsXML})
	v := verifyPatch(root, imeConfigRel, "", imeConfig("@string/input_method_subtype_label"))
	require.NotNil(t, v)
	require.Equal(t, "missing-resource", v.Rule)
	require.Contains(t, v.Detail, `<string name="input_method_subtype_label">`)

	require.Nil(t, verifyPatch(root, imeConfigRel, "", imeConfig("@string/app_name")))
	require.Nil(t, verifyPatch(root, imeConfigRel, "", imeConfig("@string/ime_label")),
		"<item type=\"string\"> declares a string too")
	require.Nil(t, verifyPatch(root, imeConfigRel, "", imeConfig("@string/abc_action_bar_up_description")),
		"library resources cannot be judged from the repository")
	require.Nil(t, verifyPatch(root, imeConfigRel, "", imeConfig("@android:string/ok")),
		"framework resources are not the repository's")
}

func TestCheckValueRefs_AcceptsDeclarationsInThePatchAndColorStateLists(t *testing.T) {
	root := writeRepo(t, map[string]string{
		stringsRel:                               stringsXML,
		"app/src/main/res/color/button_tint.xml": "<selector/>",
	})
	patchedStrings := "<resources>\n    <string name=\"app_name\">mfva</string>\n" +
		"    <string name=\"secure_label\">Secure</string>\n" +
		"    <string name=\"title\">@string/secure_label</string>\n</resources>\n"
	require.Nil(t, checkValueRefs(root, stringsRel, stringsXML, patchedStrings),
		"a value declared in the same edit exists")
	require.Nil(t, checkValueRefs(root, imeConfigRel, "", imeConfig("@color/button_tint")))
	require.NotNil(t, checkValueRefs(root, imeConfigRel, "", imeConfig("@dimen/ime_height")))
}

// fullSDK writes a platform jar holding the sentinel and the given classes.
func fullSDK(t *testing.T, classes ...string) {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, "platforms", "android-34")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	f, err := os.Create(filepath.Join(dir, "android.jar"))
	require.NoError(t, err)
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, c := range append([]string{platformSentinel}, classes...) {
		_, err := zw.Create(c)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	t.Setenv("ANDROID_HOME", home)
	t.Setenv("ANDROID_SDK_ROOT", "")
}

func imeService(imports ...string) string {
	src := "package com.appknox.mfva;\n\n"
	for _, i := range imports {
		src += "import " + i + ";\n"
	}
	return src + "\npublic class SecureInputMethodService extends InputMethodService {\n}\n"
}

// mfva PR #43: both imports named packages the platform does not have.
func TestVerifyPatch_RefusesAnAndroidClassThePlatformLacks(t *testing.T) {
	fullSDK(t,
		"android/inputmethodservice/InputMethodService.class",
		"android/view/inputmethod/EditorInfo.class",
		"android/view/WindowManager$LayoutParams.class",
	)
	root := t.TempDir()
	v := verifyPatch(root, imeServiceRel, "", imeService(
		"android.inputmethod.InputMethodService", "android.inputmethod.EditorInfo"))
	require.NotNil(t, v)
	require.Equal(t, "unknown-android-class", v.Rule)
	require.Contains(t, v.Detail, "android.inputmethod.InputMethodService does not exist "+
		"(the platform has android.inputmethodservice.InputMethodService)")
	require.Contains(t, v.Detail, "android.inputmethod.EditorInfo does not exist "+
		"(the platform has android.view.inputmethod.EditorInfo)", "both are reported at once")

	require.Nil(t, verifyPatch(root, imeServiceRel, "", imeService(
		"android.inputmethodservice.InputMethodService",
		"android.view.inputmethod.EditorInfo",
		"android.view.WindowManager.LayoutParams",  // nested class
		"android.support.v7.app.AppCompatActivity", // library, not the jar's
		"android.view.*", // wildcard names no class
	)))
}

func TestVerifyPatch_ClassCheckJudgesOnlyNewImportsAndFullJars(t *testing.T) {
	fullSDK(t)
	existing := imeService("android.inputmethod.Legacy")
	require.Nil(t, verifyPatch(t.TempDir(), imeServiceRel, existing, existing+"// edited\n"),
		"an import the file already had is not the patch's")

	// A partial jar (no sentinel) cannot prove a class absent.
	fakeSDK(t, "android/content/Intent.class", "ACTION_TIME_CHANGED")
	require.Nil(t, verifyPatch(t.TempDir(), imeServiceRel, "", imeService("android.inputmethod.InputMethodService")))
}
