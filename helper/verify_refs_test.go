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

func TestVerifyPatchRReferences(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle":                 "android {\n    namespace 'com.x'\n}\n",
		"app/src/main/res/layout/main.xml": "<LinearLayout/>\n",
		"app/src/main/java/com/x/A.kt":     "package com.x\n\nclass A\n",
	})
	p := "app/src/main/java/com/x/A.kt"
	orig := "package com.x\n\nclass A\n"
	body := func(expr string) string { return "package com.x\n\nclass A { val v = " + expr + " }\n" }

	v := verifyPatch(root, p, orig, body("R.layout.secure_keyboard"))
	require.NotNil(t, v)
	require.Equal(t, "missing-r-reference", v.Rule)
	require.Contains(t, v.Detail, "R.layout.secure_keyboard")

	for _, ok := range []string{"R.layout.main", "android.R.layout.simple_list_item_1", "com.other.R.layout.gone",
		"com.x.R.layout.main", "R.styleable.Key_label", "R.attr.colorPrimary",
		"R.string.abc_action_bar_home_description"} {
		require.Nil(t, verifyPatch(root, p, orig, body(ok)), ok)
	}
	require.NotNil(t, verifyPatch(root, p, orig, body("com.x.R.string.gone")), "the module's own qualified R is judged")

	imported := "package com.x\n\nimport com.other.R\n\nclass A { val v = R.layout.gone }\n"
	require.Nil(t, verifyPatch(root, p, orig, imported), "an imported foreign R is not this module's")
	require.Nil(t, verifyPatchWith(root, p, orig, body("R.layout.secure_keyboard"), gateOpts{deferRefs: true}))
}

// With no namespace to place it, a qualified R cannot be told from a foreign
// one and is not judged; an unqualified R is always the module's own.
func TestVerifyPatchRReferencesWithoutNamespace(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/src/main/java/com/x/A.java": "package com.x;\nclass A {}\n"})
	p := "app/src/main/java/com/x/A.java"
	orig := "package com.x;\nclass A {}\n"
	require.Nil(t, verifyPatch(root, p, orig, "package com.x;\nclass A { int v = com.x.R.layout.gone; }\n"))
	v := verifyPatch(root, p, orig, "package com.x;\nclass A { int v = R.layout.gone; }\n")
	require.NotNil(t, v)
	require.Equal(t, "missing-r-reference", v.Rule)
}

// A new ref that is a prefix of an existing one (original has R.layout.foobar,
// patch adds R.layout.foo) must be reported, not skipped as pre-existing.
func TestVerifyPatchRReferencesPrefixCollision(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle":                 "android {\n    namespace 'com.x'\n}\n",
		"app/src/main/res/layout/main.xml": "<LinearLayout/>\n",
		"app/src/main/java/com/x/A.kt":     "package com.x\n\nclass A\n",
	})
	p := "app/src/main/java/com/x/A.kt"
	orig := "package com.x\n\nclass A { val v = R.layout.foobar }\n"
	patched := "package com.x\n\nclass A { val v = R.layout.foobar; val u = R.layout.foo }\n"
	// R.layout.foo is newly added (not in original), so it should be reported as missing
	v := verifyPatch(root, p, orig, patched)
	require.NotNil(t, v, "R.layout.foo is a new reference and should be reported")
	require.Equal(t, "missing-r-reference", v.Rule)
	require.Contains(t, v.Detail, "R.layout.foo")
}

// References inside comments must not be judged.
func TestVerifyPatchRReferencesInComments(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle":                 "android {\n    namespace 'com.x'\n}\n",
		"app/src/main/res/layout/main.xml": "<LinearLayout/>\n",
		"app/src/main/java/com/x/A.kt":     "package com.x\n\nclass A\n",
	})
	p := "app/src/main/java/com/x/A.kt"
	orig := "package com.x\n\nclass A\n"

	// Line comment with missing reference: should not be reported
	patched := "package com.x\n\nclass A { // TODO use R.layout.missing\n}\n"
	require.Nil(t, verifyPatch(root, p, orig, patched), "reference in line comment")

	// Block comment with missing reference: should not be reported
	patched = "package com.x\n\nclass A { /* use R.layout.missing */ }\n"
	require.Nil(t, verifyPatch(root, p, orig, patched), "reference in block comment")
}

// References inside string and char literals must not be judged.
func TestVerifyPatchRReferencesInLiterals(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle":                 "android {\n    namespace 'com.x'\n}\n",
		"app/src/main/res/layout/main.xml": "<LinearLayout/>\n",
		"app/src/main/java/com/x/A.kt":     "package com.x\n\nclass A\n",
	})
	p := "app/src/main/java/com/x/A.kt"
	orig := "package com.x\n\nclass A\n"

	// String literal with missing reference: should not be reported
	patched := "package com.x\n\nclass A { val s = \"R.layout.missing\" }\n"
	require.Nil(t, verifyPatch(root, p, orig, patched), "reference in string literal")

	// Char literal with missing reference: should not be reported
	patched = "package com.x\n\nclass A { val c = 'R' }\n"
	require.Nil(t, verifyPatch(root, p, orig, patched), "reference in char literal")
}

// Foreign R import with trailing comment should still bail out.
func TestVerifyPatchRReferencesImportWithTrailingComment(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle":                 "android {\n    namespace 'com.x'\n}\n",
		"app/src/main/res/layout/main.xml": "<LinearLayout/>\n",
		"app/src/main/java/com/x/A.kt":     "package com.x\n\nclass A\n",
	})
	p := "app/src/main/java/com/x/A.kt"
	orig := "package com.x\n\nclass A\n"
	// Import of foreign R with trailing comment should cause early return (not judged)
	patched := "package com.x\n\nimport com.other.R; // comment\n\nclass A { val v = R.layout.missing }\n"
	require.Nil(t, verifyPatch(root, p, orig, patched), "foreign R import with trailing comment")
}

// A Kotlin string template's ${...} is code: an R reference inside one is
// compiled, so it is judged. Text around it, a $name template and a string
// nested inside the template stay literals.
func TestVerifyPatchRReferencesInKotlinTemplates(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle":                 "android {\n    namespace 'com.x'\n}\n",
		"app/src/main/res/layout/main.xml": "<LinearLayout/>\n",
		"app/src/main/java/com/x/A.kt":     "package com.x\n\nclass A\n",
	})
	p := "app/src/main/java/com/x/A.kt"
	orig := "package com.x\n\nclass A\n"
	body := func(expr string) string { return "package com.x\n\nclass A { val s = " + expr + " }\n" }

	for _, bad := range []string{
		`"Hello ${getString(R.string.missing)}!"`,
		`"""multi ${getString(R.string.missing)} line"""`,
		`"a ${if (x) { getString(R.string.missing) } else "b"} c"`,
		`"${f("x", R.string.missing)}"`,
	} {
		v := verifyPatch(root, p, orig, body(bad))
		require.NotNil(t, v, bad)
		require.Equal(t, "missing-r-reference", v.Rule, bad)
		require.Contains(t, v.Detail, "R.string.missing", bad)
	}
	for _, ok := range []string{
		`"R.string.missing $name"`,
		`"${name} R.string.missing"`,
		`"${f("R.string.missing")}"`,
		`"""R.string.missing ${name}"""`,
		`"${getString(R.layout.main)}"`,
	} {
		require.Nil(t, verifyPatch(root, p, orig, body(ok)), ok)
	}
}

// A '}' inside a string nested in a template does not close the template.
func TestCodeOnlyKotlinTemplateNestedString(t *testing.T) {
	got := codeOnly(`val s = "${f("}", R.string.a)} R.string.b"`, true)
	require.Contains(t, got, "R.string.a")
	require.NotContains(t, got, "R.string.b")
	require.Equal(t, len(`val s = "${f("}", R.string.a)} R.string.b"`), len(got), "offsets are preserved")
	require.NotContains(t, codeOnly(`String s = "${R.string.a}";`, false), "R.string.a", "Java has no templates")
}

// A class in a sub-package that uses the module's R unqualified must import it:
// R is generated in the namespace package only (allsafe-android: the new
// challenges/SecureInputMethodService.kt used R.layout.secure_keyboard with no
// import infosecadventures.allsafe.R and failed compileDebugKotlin).
func TestVerifyPatchRNotImported(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle": "android {\n    namespace 'com.x'\n}\n",
		"app/src/main/res/layout/secure_keyboard.xml": "<LinearLayout/>\n",
	})
	kt := "app/src/main/java/com/x/sub/K.kt"
	java := "app/src/main/java/com/x/sub/J.java"
	cases := []struct {
		name, path, patched string
		want                string
	}{
		{"kotlin sub-package, no import", kt,
			"package com.x.sub\n\nclass K { val v = R.layout.secure_keyboard }\n", "r-not-imported"},
		{"java sub-package, no import", java,
			"package com.x.sub;\n\nclass J { int v = R.layout.secure_keyboard; }\n", "r-not-imported"},
		{"kotlin with import", kt,
			"package com.x.sub\n\nimport com.x.R\n\nclass K { val v = R.layout.secure_keyboard }\n", ""},
		{"java with import", java,
			"package com.x.sub;\n\nimport com.x.R;\n\nclass J { int v = R.layout.secure_keyboard; }\n", ""},
		{"wildcard import", kt,
			"package com.x.sub\n\nimport com.x.*\n\nclass K { val v = R.layout.secure_keyboard }\n", ""},
		{"namespace package itself", "app/src/main/java/com/x/K.kt",
			"package com.x\n\nclass K { val v = R.layout.secure_keyboard }\n", ""},
		{"qualified reference", kt,
			"package com.x.sub\n\nclass K { val v = com.x.R.layout.secure_keyboard }\n", ""},
		{"android.R only", kt,
			"package com.x.sub\n\nclass K { val v = android.R.layout.simple_list_item_1 }\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := verifyPatchWith(root, c.path, "", c.patched, gateOpts{deferRefs: true})
			if c.want == "" {
				if v != nil {
					require.NotEqual(t, "r-not-imported", v.Rule, v.Detail)
				}
				return
			}
			require.NotNil(t, v)
			require.Equal(t, c.want, v.Rule)
			require.Contains(t, v.Detail, "import com.x.R")
		})
	}
}

// An R already in use unqualified in the original is in scope already; the
// check judges only what the patch adds.
func TestVerifyPatchRNotImportedPreexisting(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle":              "android {\n    namespace 'com.x'\n}\n",
		"app/src/main/res/layout/a.xml": "<LinearLayout/>\n",
		"app/src/main/res/layout/b.xml": "<LinearLayout/>\n",
	})
	p := "app/src/main/java/com/x/sub/K.kt"
	orig := "package com.x.sub\n\nimport com.x.*\n\nclass K { val a = R.layout.a }\n"
	patched := "package com.x.sub\n\nimport com.x.*\n\nclass K { val a = R.layout.a; val b = R.layout.b }\n"
	require.Nil(t, verifyPatchWith(root, p, orig, patched, gateOpts{deferRefs: true}))
}
