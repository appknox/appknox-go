package helper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/appknox/appknox-go/agent"
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
	require.NoError(t, w.apply(nscRel, nscBody))
	require.NoError(t, w.apply(manifestRel, manifestNSC))
	require.True(t, w.created[nscRel])
	require.Equal(t, "", w.original[nscRel])
	require.NoError(t, w.restore())
	_, err := os.Stat(filepath.Join(root, nscRel))
	require.True(t, os.IsNotExist(err))
	got, _ := readUnderRoot(root, manifestRel)
	require.Equal(t, manifestBody, got)
	require.Error(t, w.remove(manifestRel), "never deletes a file the run did not create")
}

// nscSession is mfva 113: KnoxIQ creates res/xml/network_security_config.xml
// and references it from the manifest.
func nscSession(t *testing.T, root string, locate agent.TargetReply,
	fix func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error)) fixSession {
	t.Helper()
	d := autofixDeps{
		locateTargets: func(context.Context, agent.Config, agent.TargetRequest) (agent.TargetReply, error) {
			return locate, nil
		},
		agentFix: fix,
	}
	return dryAgentSession(root, d, analysisTarget{AnalysisID: 1, Inputs: FindingInputs{
		Finding: "Cleartext traffic", VulnerabilityID: 113, Remediation: "r",
		Units: []FindingUnit{{Title: "nsc", Remediation: "create the config and reference it"}},
	}})
}

var nscReply = agent.TargetReply{
	Targets:  []agent.Target{{Path: manifestRel, Why: "reference it"}, {Path: nscRel, Why: "listed twice"}},
	NewFiles: []agent.Target{{Path: nscRel, Why: "cleartext off"}},
}

func TestRun_NewFileCreatedFirstThenReferenced(t *testing.T) {
	root := writeRepo(t, map[string]string{manifestRel: manifestBody})
	var calls []agent.FixRequest
	s := nscSession(t, root, nscReply, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		calls = append(calls, req)
		if req.Path == nscRel {
			return agent.FixResult{Changed: true, PatchedContent: nscBody}, nil
		}
		return agent.FixResult{Changed: true, PatchedContent: manifestNSC}, nil
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Len(t, calls, 2)
	require.Equal(t, nscRel, calls[0].Path, "the new file comes first")
	require.True(t, calls[0].Create)
	require.False(t, calls[1].Create)
	require.Equal(t, []agent.Target{{Path: nscRel, Why: "cleartext off", New: true}}, calls[1].OtherFiles)
	require.Equal(t, statusFixed, out.Findings[0].Status, out.Findings[0].Detail)
	require.NotContains(t, out.Findings[0].Detail, "invalid path", "the duplicate listing under targets is dropped")
	paths := []string{}
	for _, p := range out.Patches {
		paths = append(paths, p.Path)
	}
	require.ElementsMatch(t, []string{nscRel, manifestRel}, paths)
	// runAutofix's defer restores the tree after delivery; do the same here.
	require.NoError(t, s.work.restore())
	_, statErr := os.Stat(filepath.Join(root, nscRel))
	require.True(t, os.IsNotExist(statErr), "a dry run deletes the file it created")
}

// The new file is not created (declined): the manifest must not ship a
// reference to it.
func TestRun_NewFileDeclinedRollsBackTheUnit(t *testing.T) {
	root := writeRepo(t, map[string]string{manifestRel: manifestBody})
	s := nscSession(t, root, nscReply, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		if req.Path == nscRel {
			return agent.FixResult{}, nil
		}
		return agent.FixResult{Changed: true, PatchedContent: manifestBody + "<!-- other -->\n"}, nil
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusSkipped, out.Findings[0].Status, out.Findings[0].Detail)
	require.Empty(t, out.Patches)
	got, _ := readUnderRoot(root, manifestRel)
	require.Equal(t, manifestBody, got)
}

// A later target fails the gate: the created file is deleted with the rest.
func TestRun_NewFileRolledBackWhenAnotherTargetFails(t *testing.T) {
	root := writeRepo(t, map[string]string{manifestRel: manifestBody})
	s := nscSession(t, root, nscReply, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		if req.Path == nscRel {
			return agent.FixResult{Changed: true, PatchedContent: nscBody}, nil
		}
		return agent.FixResult{Changed: true, PatchedContent: "<manifest><application>\n"}, nil // malformed
	})
	res, err := s.runUnit(context.Background(), s.targets[0].Inputs, s.targets[0].Inputs.Units[0])
	require.NoError(t, err)
	require.Empty(t, res.patches)
	require.Contains(t, res.outcome.Detail, reasonRolledBack)
	_, statErr := os.Stat(filepath.Join(root, nscRel))
	require.True(t, os.IsNotExist(statErr), "the created file is deleted")
}

// The new file's content fails the gate (wrong package): nothing ships.
func TestRun_NewClassWithWrongPackageIsRefused(t *testing.T) {
	const helperRel = "app/src/main/java/com/appknox/mfva/SecureCryptoManager.java"
	const mainRel = "app/src/main/java/com/appknox/mfva/MainActivity.java"
	root := writeRepo(t, map[string]string{mainRel: "package com.appknox.mfva;\nclass MainActivity { void f() { } }\n"})
	locate := agent.TargetReply{
		Targets:  []agent.Target{{Path: mainRel, Why: "call it"}},
		NewFiles: []agent.Target{{Path: helperRel, Why: "AES-GCM helper"}},
	}
	s := nscSession(t, root, locate, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		if req.Path == helperRel {
			return agent.FixResult{Changed: true, PatchedContent: "package com.wrong;\npublic class SecureCryptoManager { }\n"}, nil
		}
		return agent.FixResult{Changed: true, PatchedContent: "package com.appknox.mfva;\nclass MainActivity { void f() { new SecureCryptoManager(); } }\n"}, nil
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusSkipped, out.Findings[0].Status, out.Findings[0].Detail)
	require.Contains(t, out.Findings[0].Detail, "new-file-package")
	require.Empty(t, out.Patches)
}

// A refused new path skips the whole finding: nothing else is attempted.
func TestRun_RefusedNewFileSkipsTheFinding(t *testing.T) {
	root := writeRepo(t, map[string]string{manifestRel: manifestBody})
	locate := agent.TargetReply{
		Targets:  []agent.Target{{Path: manifestRel, Why: "reference it"}},
		NewFiles: []agent.Target{{Path: "app/network_security_config.xml", Why: "misplaced"}},
	}
	called := false
	s := nscSession(t, root, locate, func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
		called = true
		return agent.FixResult{}, nil
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.False(t, called)
	require.Equal(t, statusSkipped, out.Findings[0].Status)
	require.True(t, strings.HasPrefix(out.Findings[0].Detail, reasonNewFileRejected), out.Findings[0].Detail)
}

// mfva 16: the second finding names the SecureCryptoManager the first already
// created. It is now an ordinary target (edited), never created twice.
func TestValidateNewFiles_ExistingBecomesTarget(t *testing.T) {
	const helperRel = "app/src/main/java/com/appknox/mfva/SecureCryptoManager.java"
	root := writeRepo(t, map[string]string{helperRel: "package com.appknox.mfva;\nclass SecureCryptoManager {}\n"})
	created, existing, rejected := validateNewFiles(root, []agent.Target{{Path: helperRel, Why: "helper"}})
	require.Empty(t, created)
	require.Empty(t, rejected)
	require.Equal(t, []agent.Target{{Path: helperRel, Why: "helper"}}, existing)
}

func TestLocateOnly_MarksNewFiles(t *testing.T) {
	root := writeRepo(t, map[string]string{manifestRel: manifestBody})
	s := nscSession(t, root, nscReply, nil)
	s.opts.LocateOnly = true
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusTargets, out.Findings[0].Status)
	require.Contains(t, out.Findings[0].Detail, nscRel+" [new] (cleartext off)")
}

// Review finding: the model lists the file under both new_files and
// needs_new_file. It is placed, so the finding is not skipped.
func TestRun_NewFileAlsoInNeedsNewFileIsStillCreated(t *testing.T) {
	root := writeRepo(t, map[string]string{manifestRel: manifestBody})
	reply := nscReply
	reply.NeedsNewFile = []string{"network_security_config.xml: disable cleartext"}
	s := nscSession(t, root, reply, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		if req.Path == nscRel {
			return agent.FixResult{Changed: true, PatchedContent: nscBody}, nil
		}
		return agent.FixResult{Changed: true, PatchedContent: manifestNSC}, nil
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusFixed, out.Findings[0].Status, out.Findings[0].Detail)
}

// Review finding: the XML is created but the manifest fixer declines. A new
// file nothing uses fixes nothing, so it must not ship.
func TestRun_OrphanNewFileRollsBack(t *testing.T) {
	root := writeRepo(t, map[string]string{manifestRel: manifestBody})
	s := nscSession(t, root, nscReply, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		if req.Path == nscRel {
			return agent.FixResult{Changed: true, PatchedContent: nscBody}, nil
		}
		return agent.FixResult{}, nil
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusSkipped, out.Findings[0].Status, out.Findings[0].Detail)
	require.Empty(t, out.Patches)
	_, statErr := os.Stat(filepath.Join(root, nscRel))
	require.True(t, os.IsNotExist(statErr))
	_, statErr = os.Stat(filepath.Join(root, "app/src/main/res/xml"))
	require.True(t, os.IsNotExist(statErr), "the directory the rollback's file needed is gone too")
}

// Review finding: a new resource in another module passes the on-disk check
// but not the build.
func TestRun_NewFileOutsideTheUsersSourceSetIsRefused(t *testing.T) {
	root := writeRepo(t, map[string]string{manifestRel: manifestBody})
	reply := agent.TargetReply{
		Targets:  []agent.Target{{Path: manifestRel, Why: "reference it"}},
		NewFiles: []agent.Target{{Path: "lib/src/main/res/xml/network_security_config.xml", Why: "wrong module"}},
	}
	called := false
	s := nscSession(t, root, reply, func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
		called = true
		return agent.FixResult{}, nil
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.False(t, called)
	require.Contains(t, out.Findings[0].Detail, "not in the source set of any file that uses it")
}

func TestRun_NewFileNeedsAgentFixMode(t *testing.T) {
	root := writeRepo(t, map[string]string{manifestRel: manifestBody})
	called := false
	s := nscSession(t, root, nscReply, func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
		called = true
		return agent.FixResult{}, nil
	})
	s.opts.FixMode = "server"
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.False(t, called, "nothing is uploaded or fixed")
	require.Contains(t, out.Findings[0].Detail, "--fix-mode agent")
}

func TestSourceSetOf(t *testing.T) {
	require.Equal(t, "app/src/main", sourceSetOf(nscRel))
	require.Equal(t, "app/src/main", sourceSetOf(manifestRel))
	require.Equal(t, "android/app/src/debug", sourceSetOf("android/app/src/debug/java/com/x/A.java"))
	require.Equal(t, "", sourceSetOf("app/build.gradle"))
}
