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
	require.True(t, libraryResource("style", "Theme.SplashScreen"))
	require.True(t, libraryResource("style", "Theme_SplashScreen_IconBackground"))
	require.True(t, libraryResource("style", "AlertDialog.AppCompat.Light"))
	require.False(t, libraryResource("style", "Theme.App"))
	require.False(t, libraryResource("string", "secure_keyboard_name"))
}

// Resources the build generates never sit in res/: resValue in a module
// script, and the google-services plugin's values. Completing one writes a
// duplicate ("Duplicate resources") or a wrong override.
func TestResourceIndex_GeneratedResources(t *testing.T) {
	groovy := "android {\n    defaultConfig {\n        resValue \"string\", \"app_name\", \"X\"\n" +
		"        resValue 'bool', \"is_debug\", 'false'\n    }\n}\n"
	kts := "android {\n    buildTypes {\n        release { resValue(\"string\", \"api_host\", \"h\") }\n    }\n}\n"
	root := writeRepo(t, map[string]string{
		"app/build.gradle":         groovy,
		"lib/build.gradle.kts":     kts,
		"app/google-services.json": "{}\n",
		"wear/build.gradle":        "android {}\n",
	})
	x := buildResourceIndex(root)
	require.True(t, x.has("string", "app_name"), "Groovy resValue")
	require.True(t, x.has("bool", "is_debug"), "Groovy resValue, single quotes")
	require.True(t, x.has("string", "api_host"), "Kotlin DSL resValue(...)")
	for _, n := range []string{"default_web_client_id", "google_app_id", "gcm_defaultSenderId", "google_api_key",
		"google_crash_reporting_api_key", "google_storage_bucket", "project_id", "firebase_database_url"} {
		require.True(t, x.has("string", n), n)
	}
	require.True(t, x.has("integer", "google_play_services_version"))

	bare := buildResourceIndex(writeRepo(t, map[string]string{"app/build.gradle": "android {}\n"}))
	require.False(t, bare.has("string", "google_app_id"), "no google-services.json, no plugin")
	require.True(t, bare.has("integer", "google_play_services_version"), "always defined")

	plugin := buildResourceIndex(writeRepo(t, map[string]string{
		"app/build.gradle.kts": "plugins {\n    id(\"com.google.gms.google-services\")\n}\n",
	}))
	require.True(t, plugin.has("string", "default_web_client_id"), "the plugin is applied")
}

// A declaration the index misses is reported unresolved, and completing it
// writes a duplicate class. Each form on its own line, as real sources have it.
func TestResourceIndex_ClassDeclarationForms(t *testing.T) {
	cases := []struct{ name, file, src, fqcn string }{
		{"Hilt-annotated Kotlin class", "K.kt",
			"package com.x\n\n@AndroidEntryPoint class MainActivity : AppCompatActivity()\n", "com.x.MainActivity"},
		{"annotated public Java class", "Foo.java", "package com.x;\n\n@Keep public class Foo {}\n", "com.x.Foo"},
		{"annotation with arguments", "Bar.java",
			"package com.x;\n\n@SuppressWarnings(\"unused\") @Keep final class Bar {}\n", "com.x.Bar"},
		{"qualified annotation", "Baz.kt", "package com.x\n\n@androidx.annotation.Keep object Baz\n", "com.x.Baz"},
		{"Java record", "Point.java", "package com.x;\n\npublic record Point(int x, int y) {}\n", "com.x.Point"},
		{"Java enum", "Mode.java", "package com.x;\n\npublic enum Mode { A, B }\n", "com.x.Mode"},
		{"Kotlin enum class", "Color.kt", "package com.x\n\nenum class Color { RED }\n", "com.x.Color"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := writeRepo(t, map[string]string{"app/src/main/java/com/x/" + c.file: c.src})
			require.True(t, buildResourceIndex(root).hasClass(c.fqcn))
		})
	}
}

// A DOCTYPE-declared entity must not stop the values file at its first use:
// every entry after it would look missing, and completion would duplicate it.
func TestResourceIndex_ValuesWithDoctypeEntities(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/src/main/res/values/strings.xml": `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE resources [
    <!ENTITY appname "Vault">
]>
<resources>
    <string name="before">x</string>
    <string name="title">&appname; settings</string>
    <string name="after">About &appname; &amp; more</string>
    <color name="accent">#fff</color>
</resources>
`,
	})
	x := buildResourceIndex(root)
	for _, n := range []string{"before", "title", "after"} {
		require.True(t, x.has("string", n), n)
	}
	require.True(t, x.has("color", "accent"), "entries after an entity use are indexed")
}

// Values files define drawables and ids too; layouts, menus and navigation
// graphs define ids with @+id.
func TestResourceIndex_ValuesDrawablesAndIDDefinitions(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/src/main/res/values/drawables.xml": "<resources>\n    <drawable name=\"scrim\">#80000000</drawable>\n" +
			"    <item type=\"drawable\" name=\"alias\">@drawable/scrim</item>\n    <item type=\"id\" name=\"spare\"/>\n</resources>\n",
		"app/src/main/res/menu/main.xml":      "<menu><item android:id=\"@+id/action_lock\"/></menu>\n",
		"app/src/main/res/navigation/nav.xml": "<navigation android:id=\"@+id/nav\"><fragment android:id=\"@+id/home\"/></navigation>\n",
	})
	x := buildResourceIndex(root)
	require.True(t, x.has("drawable", "scrim"), "<drawable name=...> in values")
	require.True(t, x.has("drawable", "alias"))
	require.True(t, x.has("id", "spare"))
	require.True(t, x.has("id", "action_lock"), "@+id in a menu")
	require.True(t, x.has("id", "home"), "@+id in a navigation graph")
}
