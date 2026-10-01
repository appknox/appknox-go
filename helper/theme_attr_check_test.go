package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ionic-conference-app: the new secure_keyboard.xml used ?attr/colorBackground,
// a framework attribute the app does not define, and processDebugResources
// failed with "resource attr/colorBackground not found".
func TestCheckThemeAttrs(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/src/main/res/values/attrs.xml": "<resources>\n  <attr name=\"brandTint\" format=\"color\"/>\n</resources>\n",
	})
	layout := "app/src/main/res/layout/k.xml"
	wrap := func(attr string) string {
		return "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
			"  android:background=\"" + attr + "\"/>\n"
	}
	cases := []struct {
		name, path, original, patched string
		want                          bool
	}{
		{"framework attr without android: prefix", layout, "", wrap("?attr/colorBackground"), true},
		{"bare ?name form", layout, "", wrap("?colorBackground"), true},
		{"android-prefixed is fine", layout, "", wrap("?android:attr/colorBackground"), false},
		{"bare ?android: form is fine", layout, "", wrap("?android:colorBackground"), false},
		{"attr defined in repo", layout, "", wrap("?attr/brandTint"), false},
		{"appcompat/material attr", layout, "", wrap("?attr/colorPrimary"), false},
		{"material textAppearance attr", layout, "", wrap("?attr/textAppearanceBody1"), false},
		{"selectableItemBackground", layout, "", wrap("?attr/selectableItemBackground"), false},
		{"already in original", layout, wrap("?attr/colorBackground"), wrap("?attr/colorBackground"), false},
		{"not xml", "app/src/main/java/A.kt", "", "val s = \"?attr/colorBackground\"\n", false},
		{"in an xml comment", layout, "", "<!-- ?attr/colorBackground -->\n<LinearLayout/>\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := checkThemeAttrs(root, c.path, c.original, c.patched)
			if !c.want {
				require.Nil(t, v)
				return
			}
			require.NotNil(t, v)
			require.Equal(t, "unresolved-theme-attr", v.Rule)
			require.Contains(t, v.Detail, "?android:attr/colorBackground")
		})
	}
}
