package helper

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Checks against a REAL android.jar, not the synthetic one the rest of the
// suite builds.
//
// The synthetic jar proves the logic; it cannot prove the premise. The premise
// is that a genuine platform jar actually distinguishes the two cases -- that
// Intent.class carries the literal ACTION_TIME_CHANGED and carries no
// ACTION_TIME_SET anywhere in its 5,981 classes. If that were false the check
// would be inert at best and a false-positive generator at worst, and every
// synthetic test would still pass.
//
// Skips unless APPKNOX_TEST_ANDROID_SDK points at an SDK, so neither CI nor a
// developer without one is broken by it. To run:
//
//	APPKNOX_TEST_ANDROID_SDK=/path/to/sdk go test ./helper/ -run RealAndroidJar -v
func realSDK(t *testing.T) {
	t.Helper()
	home := os.Getenv("APPKNOX_TEST_ANDROID_SDK")
	if home == "" {
		t.Skip("set APPKNOX_TEST_ANDROID_SDK to a real SDK to run this")
	}
	t.Setenv("ANDROID_HOME", home)
	t.Setenv("ANDROID_SDK_ROOT", "")
	require.NotEmpty(t, androidJarFor(t.TempDir()), "no platform jar under %s", home)
}

const realOriginal = `package com.example;

import android.content.Intent;
import android.content.IntentFilter;

public class TimeReceiver {
    public void register(IntentFilter f) {
    }
}
`

func patchedWith(constant string) string {
	return `package com.example;

import android.content.Intent;
import android.content.IntentFilter;

public class TimeReceiver {
    public void register(IntentFilter f) {
        f.addAction(Intent.` + constant + `);
    }
}
`
}

// The exact break seen on Fossify Calendar.
func TestRealAndroidJarRejectsTheCalendarConstant(t *testing.T) {
	realSDK(t)

	start := time.Now()
	v := verifyPatch(t.TempDir(), "src/TimeReceiver.java", realOriginal, patchedWith("ACTION_TIME_SET"))
	t.Logf("rejection path took %s (includes the whole-jar supertype scan)", time.Since(start))

	require.NotNil(t, v, "ACTION_TIME_SET does not exist and must be rejected")
	require.Equal(t, "unknown-android-symbol", v.Rule)
	require.Contains(t, v.Detail, "ACTION_TIME_SET")
}

// The constants that DO exist must all pass. ACTION_TIME_CHANGED is the one the
// fixer should have written; the other two are its neighbours.
func TestRealAndroidJarAcceptsGenuineConstants(t *testing.T) {
	realSDK(t)

	for _, c := range []string{"ACTION_TIME_CHANGED", "ACTION_TIME_TICK", "ACTION_TIMEZONE_CHANGED", "ACTION_VIEW"} {
		t.Run(c, func(t *testing.T) {
			require.Nil(t, verifyPatch(t.TempDir(), "src/TimeReceiver.java", realOriginal, patchedWith(c)),
				"%s is a real platform constant and must not be rejected", c)
		})
	}
}

// A constant declared by a SUPERTYPE lives in the supertype's class file, not
// the one named at the call site. This is the case that justifies the
// whole-jar scan in androidJar.missing, and it must pass against a real jar.
func TestRealAndroidJarAcceptsInheritedConstant(t *testing.T) {
	realSDK(t)

	original := "package com.example;\n\nimport android.app.AlertDialog;\n\npublic class A {}\n"
	patched := `package com.example;

import android.app.AlertDialog;

public class A {
    int which = AlertDialog.BUTTON_POSITIVE;
}
`
	// BUTTON_POSITIVE is declared on DialogInterface, which AlertDialog
	// implements -- so AlertDialog.class alone would not mention it.
	require.Nil(t, verifyPatch(t.TempDir(), "src/A.java", original, patched))
}
