package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/appknox/appknox-go/workspace"
	"github.com/stretchr/testify/require"
)

const (
	nscRel      = "app/src/main/res/xml/network_security_config.xml"
	manifestRel = "app/src/main/AndroidManifest.xml"
	nscBody     = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<network-security-config>\n" +
		"  <base-config cleartextTrafficPermitted=\"false\" />\n</network-security-config>\n"
	manifestBody = "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"  <application android:label=\"mfva\">\n  </application>\n</manifest>\n"
	manifestNSC = "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"  <application android:label=\"mfva\" android:networkSecurityConfig=\"@xml/network_security_config\">\n" +
		"  </application>\n</manifest>\n"
)

func TestCheckNewTarget(t *testing.T) {
	root := writeRepo(t, map[string]string{
		manifestRel: manifestBody,
		"app/src/main/java/com/appknox/mfva/MainActivity.java": "package com.appknox.mfva;\nclass MainActivity {}\n",
	})
	cases := map[string]string{
		nscRel: "",
		"app/src/main/java/com/appknox/mfva/SecureCryptoManager.java": "",
		"app/src/main/kotlin/com/x/Helper.kt":                         "",
		"app/src/debug/res/xml/debug_config.xml":                      "",
		"app/src/main/java/com/appknox/mfva/MainActivity.java":        reasonNewExists,
		"app/src/main/res/xml/Network-Config.xml":                     reasonNewResName,
		"app/src/main/res/network_security_config.xml":                reasonNewPlacement, // no <type> dir
		"app/src/main/res/xml/sub/x.xml":                              reasonNewPlacement,
		"app/network_security_config.xml":                             reasonNewPlacement,
		"app/src/main/java/Top.java":                                  reasonNewPlacement, // no package dir
		"app/src/main/assets/config.json":                             reasonNewPlacement,
		"app/src/main/res/raw/data.json":                              reasonNewUnsupported,
		"app/src/main/res/config/x.xml":                               reasonNewPlacement, // not a resource type
		"app/src/main/res/values-night/colors_extra.xml":              "",
		"app/build/generated/res/xml/x.xml":                           reasonGenerated,
		"app/build.gradle.kts":                                        reasonBuildFile,
		"../outside/x.xml":                                            reasonInvalidPath,
	}
	for p, want := range cases {
		_, got := checkNewTarget(root, p)
		require.Equal(t, want, got, p)
	}
}

func TestCheckNewFilePackage(t *testing.T) {
	p := "app/src/main/java/com/appknox/mfva/SecureCryptoManager.java"
	require.Nil(t, checkNewFilePackage(p, "", "package com.appknox.mfva;\n\npublic class SecureCryptoManager {}\n"))
	v := checkNewFilePackage(p, "", "package com.appknox;\npublic class SecureCryptoManager {}\n")
	require.NotNil(t, v)
	require.Equal(t, "new-file-package", v.Rule)
	require.NotNil(t, checkNewFilePackage(p, "", "public class SecureCryptoManager {}\n"), "missing package")
	require.Nil(t, checkNewFilePackage("app/src/main/kotlin/com/x/H.kt", "", "package com.x\n\nobject H\n"))
	// Existing files are not judged.
	require.Nil(t, checkNewFilePackage(p, "package x;\n", "package y;\n"))
}

func TestWorkingTree_CreatedFileIsDeletedOnRestore(t *testing.T) {
	root := writeRepo(t, map[string]string{manifestRel: manifestBody})
	w := newWorkingTree(root)
	applyTracked(t, w, nscRel, nscBody)
	applyTracked(t, w, manifestRel, manifestNSC)
	require.True(t, w.created[nscRel])
	require.Equal(t, "", w.original[nscRel])
	require.NoError(t, w.restore())
	_, err := os.Stat(filepath.Join(root, nscRel))
	require.True(t, os.IsNotExist(err))
	got, _ := readUnderRoot(root, manifestRel)
	require.Equal(t, manifestBody, got)
	require.Error(t, w.remove(manifestRel), "never deletes a file the run did not create")
}

// mfva 16: the second finding names the SecureCryptoManager the first already
// created. It is now an ordinary target (edited), never created twice.
func TestValidateNewFiles_ExistingBecomesTarget(t *testing.T) {
	const helperRel = "app/src/main/java/com/appknox/mfva/SecureCryptoManager.java"
	root := writeRepo(t, map[string]string{helperRel: "package com.appknox.mfva;\nclass SecureCryptoManager {}\n"})
	created, existing, rejected := validateNewFiles(root, []workspace.Target{{Path: helperRel, Why: "helper"}})
	require.Empty(t, created)
	require.Empty(t, rejected)
	require.Equal(t, []workspace.Target{{Path: helperRel, Why: "helper"}}, existing)
}

func TestSourceSetOf(t *testing.T) {
	require.Equal(t, "app/src/main", sourceSetOf(nscRel))
	require.Equal(t, "app/src/main", sourceSetOf(manifestRel))
	require.Equal(t, "android/app/src/debug", sourceSetOf("android/app/src/debug/java/com/x/A.java"))
	require.Equal(t, "", sourceSetOf("app/build.gradle"))
}
