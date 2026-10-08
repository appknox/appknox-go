package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// OpenNutriTracker (Flutter): the new SecureInputMethodSettingsActivity.kt
// extended AppCompatActivity, the app does not depend on androidx.appcompat,
// and compileDebugKotlin failed with "Unresolved reference 'AppCompatActivity'".
func TestCheckMissingLibrary(t *testing.T) {
	flutter := map[string]string{
		"android/app/build.gradle": "plugins { id 'com.android.application' }\nandroid { compileSdk 34 }\n" +
			"dependencies { implementation 'androidx.core:core-ktx:1.9.0' }\n",
	}
	withAppcompat := map[string]string{
		"app/build.gradle": "dependencies { implementation 'androidx.appcompat:appcompat:1.6.1' }\n",
	}
	viaCatalog := map[string]string{
		"app/build.gradle.kts":      "dependencies { implementation(libs.androidx.appcompat) }\n",
		"gradle/libs.versions.toml": "[libraries]\nandroidx-appcompat = { group = \"androidx.appcompat\", name = \"appcompat\" }\n",
	}
	reactNative := map[string]string{
		"android/app/build.gradle": "dependencies { implementation(\"com.facebook.react:react-android\") }\n",
	}
	withMaterial := map[string]string{
		"app/build.gradle": "dependencies { implementation 'com.google.android.material:material:1.11.0' }\n",
	}
	kt := "android/app/src/main/kotlin/com/x/S.kt"
	appcompatImport := "package com.x\n\nimport androidx.appcompat.app.AppCompatActivity\n\nclass S : AppCompatActivity()\n"
	materialImport := "package com.x\n\nimport com.google.android.material.snackbar.Snackbar\n\nclass S\n"
	cases := []struct {
		name     string
		repo     map[string]string
		original string
		patched  string
		want     bool
	}{
		{"appcompat import, no dependency (flutter)", flutter, "", appcompatImport, true},
		{"material import, no dependency", flutter, "", materialImport, true},
		{"appcompat declared", withAppcompat, "", appcompatImport, false},
		{"appcompat via version catalog", viaCatalog, "", appcompatImport, false},
		{"appcompat transitively via react-android", reactNative, "", appcompatImport, false},
		{"appcompat transitively via material", withMaterial, "", appcompatImport, false},
		{"material declared", withMaterial, "", materialImport, false},
		{"import already in original", flutter, appcompatImport, appcompatImport, false},
		{"platform Activity is fine", flutter, "", "package com.x\n\nimport android.app.Activity\n\nclass S : Activity()\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := writeRepo(t, c.repo)
			v := checkMissingLibrary(root, kt, c.original, c.patched)
			if !c.want {
				require.Nil(t, v)
				return
			}
			require.NotNil(t, v)
			require.Equal(t, "missing-library", v.Rule)
		})
	}
}

func TestDescribeBuild_saysWhenAppCompatIsAbsent(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"android/app/build.gradle": "plugins { id 'com.android.application' }\nandroid { compileSdk 34 }\n",
	})
	require.Contains(t, describeBuild(root).String(), "androidx.appcompat is NOT a dependency")

	root = writeRepo(t, map[string]string{
		"app/build.gradle": "android { compileSdk 34 }\ndependencies { implementation 'androidx.appcompat:appcompat:1.6.1' }\n",
	})
	require.NotContains(t, describeBuild(root).String(), "appcompat")
}
