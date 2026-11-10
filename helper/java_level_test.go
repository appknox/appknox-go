package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// mfva verify run 36089101135: autofix's MyApplication.java used
// `new Thread(() -> {...})`, and the build failed with "lambda expressions are
// not supported in -source 1.7". mfva declares no compileOptions and builds
// with AGP 3.4.2, whose default language level is Java 7.
const mfvaRootGradle = "buildscript {\n dependencies {\n  classpath 'com.android.tools.build:gradle:3.4.2'\n }\n}\n"

const lambdaApp = `package com.appknox.mfva;

public class MyApplication extends android.app.Application {
    public void onCreate() {
        new Thread(() -> check()).start();
    }
}
`

const anonymousApp = `package com.appknox.mfva;

public class MyApplication extends android.app.Application {
    public void onCreate() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                check();
            }
        }).start();
    }
}
`

func TestJavaLanguageLevel(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		want  int
	}{
		"AGP 3 default": {map[string]string{"build.gradle": mfvaRootGradle, "app/build.gradle": "android {}\n"}, 7},
		"AGP 4.1 default": {map[string]string{
			"build.gradle": "classpath 'com.android.tools.build:gradle:4.1.3'\n"}, 7},
		"AGP 4.2 default": {map[string]string{
			"build.gradle": "classpath 'com.android.tools.build:gradle:4.2.0'\n"}, 8},
		"AGP 8 default": {map[string]string{
			"build.gradle": "classpath 'com.android.tools.build:gradle:8.1.0'\n"}, 8},
		"explicit 1.8 on AGP 3": {map[string]string{
			"build.gradle":     mfvaRootGradle,
			"app/build.gradle": "android { compileOptions { sourceCompatibility JavaVersion.VERSION_1_8 } }\n"}, 8},
		"explicit 17 kts": {map[string]string{
			"build.gradle.kts":     "plugins { id(\"com.android.application\") version \"8.2.0\" }\n",
			"app/build.gradle.kts": "android { compileOptions { sourceCompatibility = JavaVersion.VERSION_17 } }\n"}, 17},
		"string form": {map[string]string{
			"build.gradle":     mfvaRootGradle,
			"app/build.gradle": "sourceCompatibility = '1.8'\n"}, 8},
		"toolchain": {map[string]string{
			"build.gradle":     mfvaRootGradle,
			"app/build.gradle": "kotlin { jvmToolchain(11) }\n"}, 11},
		"unreadable": {map[string]string{"app/build.gradle": "android {}\n"}, 0},
	}
	for name, c := range cases {
		require.Equal(t, c.want, javaLanguageLevel(writeRepo(t, c.files)), name)
	}
}

func TestVerifyPatchRefusesLambdaBelowJava8(t *testing.T) {
	root := writeRepo(t, map[string]string{"build.gradle": mfvaRootGradle, "app/build.gradle": "android {}\n"})
	path := "app/src/main/java/com/appknox/mfva/MyApplication.java"

	v := verifyPatch(root, path, "", lambdaApp)
	require.NotNil(t, v)
	require.Equal(t, "java-language-level", v.Rule)
	require.Contains(t, v.Detail, "Java 7")

	methodRef := "package a;\nclass A { void f() { run(this::g); } }\n"
	require.NotNil(t, verifyPatch(root, "app/src/main/java/a/A.java", "", methodRef))

	require.Nil(t, verifyPatch(root, path, "", anonymousApp), "an anonymous class is Java 7")
	require.Nil(t, verifyPatch(root, "app/src/main/java/a/B.java", "",
		"package a;\nclass B { String s = \"a -> b :: c\"; } // x -> y\n"), "text in strings and comments is not syntax")
}

func TestVerifyPatchAllowsLambdaWhenJava8(t *testing.T) {
	path := "app/src/main/java/com/appknox/mfva/MyApplication.java"
	explicit := writeRepo(t, map[string]string{"build.gradle": mfvaRootGradle,
		"app/build.gradle": "android { compileOptions { sourceCompatibility JavaVersion.VERSION_1_8 } }\n"})
	require.Nil(t, verifyPatch(explicit, path, "", lambdaApp))

	unknown := writeRepo(t, map[string]string{"app/build.gradle": "android {}\n"})
	require.Nil(t, verifyPatch(unknown, path, "", lambdaApp), "unreadable level: abstain")
}

// A lambda the file already had is not this patch's doing.
func TestVerifyPatchIgnoresExistingLambda(t *testing.T) {
	root := writeRepo(t, map[string]string{"build.gradle": mfvaRootGradle})
	path := "app/src/main/java/com/appknox/mfva/MyApplication.java"
	patched := lambdaApp + "// fixed\n"
	require.Nil(t, verifyPatch(root, path, lambdaApp, patched))
}
