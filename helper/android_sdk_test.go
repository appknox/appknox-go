package helper

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeSDK writes an android.jar containing one class whose bytes carry the
// given symbol names, and points ANDROID_HOME at it.
//
// The bytes need not be a real class file: the check asks only whether a name
// occurs in them, which is the whole point of that design -- see
// classMentionsSymbol.
func fakeSDK(t *testing.T, class string, symbols ...string) {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, "platforms", "android-34")
	require.NoError(t, os.MkdirAll(dir, 0o755))

	f, err := os.Create(filepath.Join(dir, "android.jar"))
	require.NoError(t, err)
	defer f.Close()

	zw := zip.NewWriter(f)
	w, err := zw.Create(class)
	require.NoError(t, err)
	// A plausible constant pool: names separated by non-printable bytes.
	for _, s := range symbols {
		_, err = w.Write([]byte("\x01\x00" + s))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())

	t.Setenv("ANDROID_HOME", home)
	t.Setenv("ANDROID_SDK_ROOT", "") // a real SDK on the dev machine must not leak in
}

// installLevels writes an SDK holding a platform jar for each given API level,
// every one carrying the same symbol, and points ANDROID_HOME at it.
func installLevels(t *testing.T, levels ...int) {
	t.Helper()
	home := t.TempDir()
	for _, level := range levels {
		dir := filepath.Join(home, "platforms", fmt.Sprintf("android-%d", level))
		require.NoError(t, os.MkdirAll(dir, 0o755))

		f, err := os.Create(filepath.Join(dir, "android.jar"))
		require.NoError(t, err)
		zw := zip.NewWriter(f)
		w, err := zw.Create("android/content/Intent.class")
		require.NoError(t, err)
		_, err = w.Write([]byte("\x01\x00ACTION_TIME_CHANGED"))
		require.NoError(t, err)
		require.NoError(t, zw.Close())
		require.NoError(t, f.Close())
	}
	t.Setenv("ANDROID_HOME", home)
	t.Setenv("ANDROID_SDK_ROOT", "")
}

// repoWithCompileSdk returns a repo root whose build.gradle names a level.
func repoWithCompileSdk(t *testing.T, level int) string {
	t.Helper()
	root := t.TempDir()
	gradle := fmt.Sprintf("android {\n    compileSdkVersion %d\n}\n", level)
	require.NoError(t, os.WriteFile(filepath.Join(root, "build.gradle"), []byte(gradle), 0o644))
	return root
}

// The platform the repo actually compiles against is the right one to judge it.
func TestAndroidJarForPrefersTheRepoCompileSdk(t *testing.T) {
	installLevels(t, 30, 34, 36)

	got := androidJarFor(repoWithCompileSdk(t, 34))

	require.Contains(t, got, filepath.Join("platforms", "android-34"))
}

// A jar OLDER than the repo's compileSdk cannot see constants added since, so
// judging against it would reject correct patches. Abstain instead.
func TestAndroidJarForAbstainsWhenSDKPredatesCompileSdk(t *testing.T) {
	installLevels(t, 30, 31)

	require.Empty(t, androidJarFor(repoWithCompileSdk(t, 35)))
}

// A newer jar is a superset of what the repo may reference, so it is safe.
func TestAndroidJarForAcceptsNewerPlatformThanCompileSdk(t *testing.T) {
	installLevels(t, 35, 36)

	got := androidJarFor(repoWithCompileSdk(t, 34))

	require.Contains(t, got, filepath.Join("platforms", "android-36"))
}

// With no compileSdk to read, the fullest jar installed is the best available.
func TestAndroidJarForFallsBackToNewestWithoutCompileSdk(t *testing.T) {
	installLevels(t, 33, 35)

	got := androidJarFor(t.TempDir()) // no build.gradle at all

	require.Contains(t, got, filepath.Join("platforms", "android-35"))
}

// compileSdk = 34 and compileSdk 34 are both legal Gradle; so is the Version suffix.
func TestRepoCompileSdkReadsEverySpelling(t *testing.T) {
	for _, decl := range []string{"compileSdkVersion 34", "compileSdk 34", "compileSdk = 34"} {
		t.Run(decl, func(t *testing.T) {
			root := t.TempDir()
			body := "android {\n    " + decl + "\n}\n"
			require.NoError(t, os.WriteFile(filepath.Join(root, "build.gradle.kts"), []byte(body), 0o644))

			require.Equal(t, 34, repoCompileSdk(root))
		})
	}
}

const calendarOriginal = `package com.example;

import android.content.Intent;
import android.content.IntentFilter;

public class TimeReceiver {
    public void register() {
        IntentFilter f = new IntentFilter();
    }
}
`

// Fossify Calendar, 2026-09-11: the fixer added Intent.ACTION_TIME_SET, which
// does not exist. android.content.Intent declares ACTION_TIME_CHANGED, whose
// *string value* is "android.intent.action.TIME_SET" -- the name and the value
// disagree, and the fixer took the value for the name.
func TestVerifyPatchRejectsInventedPlatformConstant(t *testing.T) {
	fakeSDK(t, "android/content/Intent.class",
		"ACTION_TIME_TICK", "ACTION_TIME_CHANGED", "ACTION_TIMEZONE_CHANGED")

	patched := `package com.example;

import android.content.Intent;
import android.content.IntentFilter;

public class TimeReceiver {
    public void register() {
        IntentFilter f = new IntentFilter();
        f.addAction(Intent.ACTION_TIME_SET);
    }
}
`
	v := verifyPatch(t.TempDir(), "src/TimeReceiver.java", calendarOriginal, patched)

	require.NotNil(t, v)
	require.Equal(t, "unknown-android-symbol", v.Rule)
	require.Contains(t, v.Detail, "ACTION_TIME_SET")
}

// The neighbouring constant that DOES exist must pass, or the check would cost
// the same repo the fix it is meant to protect.
func TestVerifyPatchAcceptsRealPlatformConstant(t *testing.T) {
	fakeSDK(t, "android/content/Intent.class",
		"ACTION_TIME_TICK", "ACTION_TIME_CHANGED", "ACTION_TIMEZONE_CHANGED")

	patched := `package com.example;

import android.content.Intent;
import android.content.IntentFilter;

public class TimeReceiver {
    public void register() {
        IntentFilter f = new IntentFilter();
        f.addAction(Intent.ACTION_TIME_CHANGED);
    }
}
`
	require.Nil(t, verifyPatch(t.TempDir(), "src/TimeReceiver.java", calendarOriginal, patched))
}

// No SDK on the machine means the check cannot decide, and a check that cannot
// decide must not reject -- the rule the 2026-09-11 run established.
func TestVerifyPatchAbstainsWithoutAndroidSDK(t *testing.T) {
	t.Setenv("ANDROID_HOME", t.TempDir()) // exists, but holds no platform
	t.Setenv("ANDROID_SDK_ROOT", "")

	patched := `package com.example;

import android.content.Intent;

public class TimeReceiver {
    public void register() {
        f.addAction(Intent.ACTION_TIME_SET);
    }
}
`
	require.Nil(t, verifyPatch(t.TempDir(), "src/TimeReceiver.java", calendarOriginal, patched))
}

// A class the jar does not carry is not the platform's, so it cannot be judged
// from the platform jar.
func TestVerifyPatchAbstainsForClassNotInTheJar(t *testing.T) {
	fakeSDK(t, "android/content/Intent.class", "ACTION_TIME_CHANGED")

	original := "package com.example;\n\npublic class A {}\n"
	patched := `package com.example;

import android.provider.CalendarContract;

public class A {
    String x = CalendarContract.INVENTED_THING;
}
`
	require.Nil(t, verifyPatch(t.TempDir(), "src/A.java", original, patched))
}

// A constant on a class the file never imported from android.* is the app's
// own, and the platform jar has no opinion about it.
func TestVerifyPatchIgnoresNonPlatformConstants(t *testing.T) {
	fakeSDK(t, "android/content/Intent.class", "ACTION_TIME_CHANGED")

	original := "package com.example;\n\npublic class A {}\n"
	patched := `package com.example;

import com.example.util.Config;

public class A {
    String x = Config.TOTALLY_MADE_UP;
}
`
	require.Nil(t, verifyPatch(t.TempDir(), "src/A.java", original, patched))
}

// Rule 1 of this gate: judge only what the patch added. A bad constant the
// repository already contained is not the fixer's to answer for.
func TestVerifyPatchIgnoresPreExistingPlatformConstants(t *testing.T) {
	fakeSDK(t, "android/content/Intent.class", "ACTION_TIME_CHANGED")

	original := `package com.example;

import android.content.Intent;

public class A {
    String x = Intent.ACTION_TIME_SET;
}
`
	patched := original + "\n// a comment the fixer added\n"

	require.Nil(t, verifyPatch(t.TempDir(), "src/A.java", original, patched))
}

// Kotlin gets the same treatment; the corpus is roughly half Kotlin.
func TestVerifyPatchRejectsInventedPlatformConstantInKotlin(t *testing.T) {
	fakeSDK(t, "android/content/Intent.class", "ACTION_TIME_CHANGED")

	original := "package com.example\n\nimport android.content.Intent\n\nclass A\n"
	patched := `package com.example

import android.content.Intent

class A {
    val x = Intent.ACTION_TIME_SET
}
`
	v := verifyPatch(t.TempDir(), "src/A.kt", original, patched)

	require.NotNil(t, v)
	require.Equal(t, "unknown-android-symbol", v.Rule)
}

// Non-JVM files must not be scanned at all.
func TestVerifyPatchSkipsAndroidSymbolsForXML(t *testing.T) {
	fakeSDK(t, "android/content/Intent.class", "ACTION_TIME_CHANGED")

	original := "<resources></resources>\n"
	patched := "<resources><string name=\"a\">Intent.ACTION_TIME_SET</string></resources>\n"

	require.Nil(t, verifyPatch(t.TempDir(), "res/values/strings.xml", original, patched))
}
