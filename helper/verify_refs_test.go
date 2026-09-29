package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyPatchResourceKinds(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/src/main/res/xml/cfg.xml":                 "<input-method/>\n",
		"app/src/main/res/values/strings.xml":          "<resources><string name=\"app_name\">x</string></resources>\n",
		"app/src/main/res/values/styles.xml":           "<resources><style name=\"Theme.App\"/></resources>\n",
		"app/src/main/res/mipmap-hdpi/ic_launcher.png": "png",
	})
	p := "app/src/main/res/xml/cfg.xml"
	label := func(v string) string {
		return "<input-method xmlns:android=\"http://schemas.android.com/apk/res/android\" android:label=\"" + v + "\"/>\n"
	}
	for _, ok := range []string{"@string/app_name", "@style/Theme.App", "@mipmap/ic_launcher",
		"@android:string/ok", "@style/Theme.AppCompat.Light", "@string/abc_action_bar_home_description"} {
		require.Nil(t, verifyPatch(root, p, "<input-method/>\n", label(ok)), ok)
	}
	for _, bad := range []string{"@string/secure_keyboard_name", "@dimen/key_height", "@color/key_bg",
		"@font/mono", "@navigation/nav"} {
		v := verifyPatch(root, p, "<input-method/>\n", label(bad))
		require.NotNil(t, v, bad)
		require.Equal(t, "missing-resource", v.Rule)
		require.Contains(t, v.Detail, bad)
	}
}

// Resource syntax inside a Java string is not a resource reference.
func TestVerifyPatchResourceRefsOnlyInXML(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/java/A.java": "class A {}\n"})
	require.Nil(t, verifyPatch(root, "app/src/main/java/A.java", "class A {}\n",
		"class A { String s = \"@string/nope\"; }\n"))
}

// Inside a unit the defining file may not be written yet: the unit's resolve
// pass judges the reference instead (spec 3.2).
func TestVerifyPatchWith_DeferRefs(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/res/xml/cfg.xml": "<input-method/>\n"})
	p := "app/src/main/res/xml/cfg.xml"
	patched := "<input-method xmlns:android=\"http://schemas.android.com/apk/res/android\"" +
		" android:label=\"@string/secure_keyboard_name\"/>\n"
	require.Nil(t, verifyPatchWith(root, p, "<input-method/>\n", patched, gateOpts{deferRefs: true}))
	v := verifyPatchWith(root, p, "<input-method/>\n", patched, gateOpts{})
	require.NotNil(t, v)
	require.Equal(t, "missing-resource", v.Rule)
}
