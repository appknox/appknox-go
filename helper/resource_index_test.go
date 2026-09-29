package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResourceIndex_ValuesFilesAndIDs(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/src/main/res/values/strings.xml": `<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">x</string>
    <string-array name="planets"><item>a</item></string-array>
    <item type="id" name="spare"/>
    <style name="Theme.App" parent="Theme.Material3.DayNight"/>
</resources>
`,
		"app/src/main/res/values-night/colors.xml": "<resources><color name=\"bg\">#000</color></resources>\n",
		"app/src/main/res/layout-land/main.xml": "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"" +
			" android:id=\"@+id/root\"/>\n",
		"app/src/main/res/drawable-nodpi/bg.9.png":      "png",
		"app/build/intermediates/res/values/values.xml": "<resources><string name=\"generated\">g</string></resources>\n",
	})
	x := buildResourceIndex(root)
	require.True(t, x.has("string", "app_name"))
	require.True(t, x.has("array", "planets"), "string-array is R.array")
	require.True(t, x.has("id", "spare"), "item type=id")
	require.True(t, x.has("style", "Theme.App"))
	require.True(t, x.has("style", "Theme_App"), "R.style.Theme_App is the same style")
	require.True(t, x.has("color", "bg"), "qualified values dir")
	require.True(t, x.has("layout", "main"), "qualified layout dir")
	require.True(t, x.has("id", "root"), "@+id in a layout")
	require.True(t, x.has("drawable", "bg"), "a nine-patch is named before its first dot")
	require.False(t, x.has("string", "generated"), "build output is pruned")
	require.False(t, x.has("string", "missing"))
}

func TestResourceIndex_Classes(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/src/main/java/com/x/Main.java": "package com.x;\n\npublic class Main {}\n",
		"app/src/main/java/com/x/Util.kt":   "package com.x\n\nobject Helpers\ninternal class Other\n",
	})
	x := buildResourceIndex(root)
	require.True(t, x.hasClass("com.x.Main"))
	require.True(t, x.hasClass("com.x.Helpers"))
	require.True(t, x.hasClass("com.x.Other"), "a Kotlin file may declare classes it is not named after")
	require.False(t, x.hasClass("com.x.Util"), "a file name is not a class")
}

func TestLibraryResource(t *testing.T) {
	require.True(t, libraryResource("style", "Theme.AppCompat.Light"))
	require.True(t, libraryResource("style", "Theme_MaterialComponents_DayNight"))
	require.True(t, libraryResource("string", "abc_action_bar_home_description"))
	require.True(t, libraryResource("color", "mtrl_btn_bg"))
	require.False(t, libraryResource("style", "Theme.App"))
	require.False(t, libraryResource("string", "secure_keyboard_name"))
}
