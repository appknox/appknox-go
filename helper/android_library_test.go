package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	baseActivityRel = "app/src/main/java/com/appknox/mfva/SecureBaseActivity.java"
	supportGradle   = "android {\n    compileSdkVersion 26\n}\ndependencies {\n" +
		"    api 'com.android.support:appcompat-v7:26.1.0'\n}\n"
	androidXGradle = "android {\n    compileSdk 34\n}\ndependencies {\n" +
		"    implementation 'androidx.appcompat:appcompat:1.6.1'\n}\n"
	supportActivity = "package com.appknox.mfva;\n\nimport android.support.v7.app.AppCompatActivity;\n\n" +
		"public class MainActivity extends AppCompatActivity {\n}\n"
	androidXActivity = "package com.appknox.mfva;\n\nimport androidx.appcompat.app.AppCompatActivity;\n\n" +
		"public class MainActivity extends AppCompatActivity {\n}\n"
)

func baseActivity(importLine string) string {
	return "package com.appknox.mfva;\n\nimport android.os.Bundle;\n" + importLine + "\n\n" +
		"public abstract class SecureBaseActivity extends AppCompatActivity {\n}\n"
}

func TestLibraryEvidence_Verdict(t *testing.T) {
	cases := []struct {
		name string
		e    libraryEvidence
		want androidLibrary
	}{
		{"support only", libraryEvidence{buildSupport: true, sourceSupport: true}, libSupport},
		{"androidx property only", libraryEvidence{useAndroidX: true}, libAndroidX},
		{"androidx sources only", libraryEvidence{sourceAndroidX: true}, libAndroidX},
		{"mixed is unknown", libraryEvidence{buildSupport: true, sourceAndroidX: true}, libUnknown},
		{"silent is unknown", libraryEvidence{}, libUnknown},
	}
	for _, c := range cases {
		require.Equal(t, c.want, c.e.verdict(), c.name)
	}
}

// mfva PR #42: the new base class imported AndroidX in a Support Library project.
func TestVerifyPatch_RefusesAndroidXInASupportProject(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle": supportGradle,
		mainRel:            supportActivity,
	})
	v := verifyPatch(root, baseActivityRel, "",
		baseActivity("import androidx.appcompat.app.AppCompatActivity;"))
	require.NotNil(t, v)
	require.Equal(t, "androidx-in-support-project", v.Rule)
	require.Contains(t, v.Detail, "android.support.v7.app.AppCompatActivity; use that",
		"the retry is told the import the project uses")

	require.Nil(t, verifyPatch(root, baseActivityRel, "",
		baseActivity("import android.support.v7.app.AppCompatActivity;")))
}

func TestVerifyPatch_RefusesSupportLibraryInAnAndroidXProject(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle":  androidXGradle,
		"gradle.properties": "android.useAndroidX=true\n",
		mainRel:             androidXActivity,
	})
	v := verifyPatch(root, baseActivityRel, "",
		baseActivity("import android.support.v7.app.AppCompatActivity;"))
	require.NotNil(t, v)
	require.Equal(t, "support-library-in-androidx-project", v.Rule)
	require.Contains(t, v.Detail, "androidx.appcompat.app.AppCompatActivity")
}

func TestCheckAndroidLibraryImports_NoVerdictWhenTheProjectIsMixed(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle": supportGradle,
		mainRel:            androidXActivity, // a source on AndroidX: the files disagree
	})
	require.Nil(t, checkAndroidLibraryImports(root, baseActivityRel, "",
		baseActivity("import androidx.appcompat.app.AppCompatActivity;")))
}

func TestCheckAndroidLibraryImports_JudgesOnlyWhatThePatchAdded(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/build.gradle": supportGradle, mainRel: supportActivity})
	existing := baseActivity("import androidx.annotation.Keep;")
	require.Nil(t, checkAndroidLibraryImports(root, baseActivityRel, existing, existing+"// edited\n"))
	require.Nil(t, checkAndroidLibraryImports(root, "app/src/main/AndroidManifest.xml", "",
		"<!-- import androidx.core -->"), "only Java and Kotlin sources are judged")
}

func TestBuildProfile_StatesTheAndroidLibrary(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/build.gradle": supportGradle, mainRel: supportActivity})
	require.Contains(t, describeBuild(root).String(),
		"Android library: Support Library (android.support.*), NOT AndroidX.")

	root = writeRepo(t, map[string]string{"app/build.gradle": androidXGradle, mainRel: androidXActivity})
	require.Contains(t, describeBuild(root).String(), "Android library: AndroidX (androidx.*).")

	root = writeRepo(t, map[string]string{"app/build.gradle": supportGradle, mainRel: androidXActivity})
	require.NotContains(t, describeBuild(root).String(), "Android library:",
		"a mixed project states nothing")
}
