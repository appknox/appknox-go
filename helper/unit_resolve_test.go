package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/stretchr/testify/require"
)

// Keylogger Protection (133), as dvfa, PeopleInSpace and vuln-bank-mobile
// received it: an input method service, its config XML and a manifest entry.
const (
	imeGradle    = "android {\n    namespace 'com.x'\n}\n"
	imeClassRel  = "app/src/main/java/com/x/SecureIME.java"
	imeClass     = "package com.x;\n\npublic class SecureIME {}\n"
	imeConfigRel = "app/src/main/res/xml/input_method_config.xml"
	imeConfigRef = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
		"<input-method xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
		"    android:label=\"@string/secure_keyboard_name\" />\n"
	imeConfigLit = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
		"<input-method xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
		"    android:label=\"Secure keyboard\" />\n"
	stringsRel  = "app/src/main/res/values/strings.xml"
	stringsBody = "<resources>\n    <string name=\"app_name\">x</string>\n</resources>\n"
	stringsDone = "<resources>\n    <string name=\"app_name\">x</string>\n" +
		"    <string name=\"secure_keyboard_name\">Secure keyboard</string>\n</resources>\n"
	imeService = "    <service android:name=\".SecureIME\" android:exported=\"true\"" +
		" android:permission=\"android.permission.BIND_INPUT_METHOD\">\n" +
		"      <intent-filter><action android:name=\"android.view.InputMethod\" /></intent-filter>\n"
	manifestSvc = "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"  <application android:label=\"mfva\">\n" + imeService + "    </service>\n  </application>\n</manifest>\n"
	manifestIME = "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
		"  <application android:label=\"mfva\">\n" + imeService +
		"      <meta-data android:name=\"android.view.im\" android:resource=\"@xml/input_method_config\" />\n" +
		"    </service>\n  </application>\n</manifest>\n"
)

func imeRepo(t *testing.T, extra map[string]string) string {
	t.Helper()
	files := map[string]string{"app/build.gradle": imeGradle, manifestRel: manifestBody, stringsRel: stringsBody}
	for k, v := range extra {
		files[k] = v
	}
	return writeRepo(t, files)
}

var imeReply = agent.TargetReply{
	Targets:  []agent.Target{{Path: manifestRel, Why: "declare the input method"}},
	NewFiles: []agent.Target{{Path: imeConfigRel, Why: "the input method's config"}},
}

// outcomePatchPaths lists the paths of an Outcome's patches. Named apart from
// the pre-existing patchPaths(patches []filePatch) string in autofix.go
// (joins for display) -- same name, different signature, so it cannot be
// reused here; this is the brief's helper of the same name, renamed to avoid
// the collision.
func outcomePatchPaths(out Outcome) []string {
	paths := []string{}
	for _, p := range out.Patches {
		paths = append(paths, p.Path)
	}
	return paths
}

func TestUnresolvedUnitRefs(t *testing.T) {
	kt := "app/src/main/java/com/x/K.kt"
	root := imeRepo(t, map[string]string{
		imeConfigRel: imeConfigRef,
		manifestRel:  manifestIME,
		kt: "package com.x\n\nclass K { val a = R.layout.gone; val b = android.R.layout.simple_list_item_1; " +
			"val c = R.string.app_name }\n",
	})
	before := map[string]string{manifestRel: manifestBody, kt: "package com.x\n\nclass K\n"}
	got := unresolvedUnitRefs(root, []string{imeConfigRel, manifestRel, kt}, before)
	require.Equal(t, []unresolvedRef{
		{Kind: "string", Name: "secure_keyboard_name", From: imeConfigRel},
		{Kind: "class", Name: "com.x.SecureIME", From: manifestRel},
		{Kind: "layout", Name: "gone", From: kt},
	}, got)
	require.Equal(t, "@string/secure_keyboard_name", got[0].String())
	require.Equal(t, "R.layout.gone", got[2].String())
}

func TestCompletionTarget(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle":                   imeGradle,
		stringsRel:                           stringsBody,
		"app/src/main/java/com/x/Main.kt":    "package com.x\n\nclass Main\n",
		"lib/build.gradle":                   "android {\n    namespace 'com.x.lib'\n}\n",
		"lib/src/main/java/com/x/lib/L.java": "package com.x.lib;\n\nclass L {}\n",
	})
	from := "app/src/main/res/xml/cfg.xml"
	cases := []struct {
		ref   unresolvedRef
		path  string
		isNew bool
		ok    bool
	}{
		{unresolvedRef{"string", "secure_keyboard_name", from}, stringsRel, false, true},
		{unresolvedRef{"dimen", "key_height", from}, "app/src/main/res/values/dimens.xml", true, true},
		{unresolvedRef{"style", "Theme.Secure", from}, "app/src/main/res/values/styles.xml", true, true},
		{unresolvedRef{"layout", "secure_keyboard", "app/src/main/java/com/x/Main.kt"},
			"app/src/main/res/layout/secure_keyboard.xml", true, true},
		{unresolvedRef{"class", "com.x.SecureIME", manifestRel}, "app/src/main/java/com/x/SecureIME.kt", true, true},
		{unresolvedRef{"class", "com.x.lib.Svc", "lib/src/main/AndroidManifest.xml"},
			"lib/src/main/java/com/x/lib/Svc.java", true, true},
		{unresolvedRef{"raw", "keys", from}, "", false, false},
		{unresolvedRef{"layout", "Bad-Name", from}, "", false, false},
		{unresolvedRef{"string", "x", "tools/cfg.xml"}, "", false, false},
	}
	for _, c := range cases {
		got, ok := completionTarget(root, c.ref)
		require.Equal(t, c.ok, ok, c.ref.String())
		if !ok {
			continue
		}
		require.Equal(t, c.path, got.Path)
		require.Equal(t, c.isNew, got.New, c.path)
		require.Contains(t, got.Why, "completion:")
	}
}

// dvfa: the config names @string/secure_keyboard_name, which nothing defines.
// Completion adds it to strings.xml, and the unit lands.
func TestRun_CompletionDefinesAMissingString(t *testing.T) {
	root := imeRepo(t, map[string]string{imeClassRel: imeClass})
	s := nscSession(t, root, imeReply, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		switch req.Path {
		case imeConfigRel:
			return agent.FixResult{Changed: true, PatchedContent: imeConfigRef}, nil
		case manifestRel:
			return agent.FixResult{Changed: true, PatchedContent: manifestIME}, nil
		case stringsRel:
			require.False(t, req.Create)
			require.Contains(t, req.Why, "@string/secure_keyboard_name")
			return agent.FixResult{Changed: true, PatchedContent: stringsDone}, nil
		}
		return agent.FixResult{}, errors.New("unexpected fix call for " + req.Path)
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusFixed, out.Findings[0].Status, out.Findings[0].Detail)
	require.Contains(t, out.Findings[0].Detail, stringsRel+" (completion)")
	require.ElementsMatch(t, []string{imeConfigRel, manifestRel, stringsRel}, outcomePatchPaths(out))
	require.NoError(t, s.work.restore())
}

// The completion declines; the config is re-fixed with the literal instead,
// and ships as ONE patch holding the final content.
func TestRun_CompletionDeclinedInlinesTheLiteral(t *testing.T) {
	root := imeRepo(t, map[string]string{imeClassRel: imeClass})
	var prior string
	s := nscSession(t, root, imeReply, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		switch {
		case req.Path == imeConfigRel && req.PriorViolation != "":
			prior = req.PriorViolation
			return agent.FixResult{Changed: true, PatchedContent: imeConfigLit}, nil
		case req.Path == imeConfigRel:
			return agent.FixResult{Changed: true, PatchedContent: imeConfigRef}, nil
		case req.Path == manifestRel:
			return agent.FixResult{Changed: true, PatchedContent: manifestIME}, nil
		}
		return agent.FixResult{}, nil // strings.xml: declined
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusFixed, out.Findings[0].Status, out.Findings[0].Detail)
	require.Contains(t, prior, "@string/secure_keyboard_name")
	require.Contains(t, prior, "literal")
	require.NotContains(t, out.Findings[0].Detail, "(completion)")
	require.ElementsMatch(t, []string{imeConfigRel, manifestRel}, outcomePatchPaths(out))
	for _, p := range out.Patches {
		if p.Path == imeConfigRel {
			require.Equal(t, imeConfigLit, p.Content)
		}
	}
	require.NoError(t, s.work.restore())
}

// Neither defined nor inlined after two rounds: the unit rolls back whole.
func TestRun_UnresolvedAfterTwoRoundsRollsBack(t *testing.T) {
	root := imeRepo(t, map[string]string{imeClassRel: imeClass})
	calls := 0
	s := nscSession(t, root, imeReply, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		calls++
		switch {
		case req.Path == imeConfigRel && req.PriorViolation == "":
			return agent.FixResult{Changed: true, PatchedContent: imeConfigRef}, nil
		case req.Path == manifestRel:
			return agent.FixResult{Changed: true, PatchedContent: manifestIME}, nil
		}
		return agent.FixResult{}, nil
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, 6, calls, "config, manifest, then strings.xml and the config re-fix in each of 2 rounds")
	require.Equal(t, statusSkipped, out.Findings[0].Status)
	require.Contains(t, out.Findings[0].Detail,
		"rolled back: unresolved @string/secure_keyboard_name after 2 completion rounds")
	require.Empty(t, out.Patches)
	got, _ := readUnderRoot(root, manifestRel)
	require.Equal(t, manifestBody, got)
	_, statErr := os.Stat(filepath.Join(root, imeConfigRel))
	require.True(t, os.IsNotExist(statErr))
}

// PeopleInSpace: a new Kotlin service uses R.layout.secure_keyboard; the
// completion creates that layout.
func TestRun_CompletionCreatesAMissingLayout(t *testing.T) {
	kt := "app/src/main/java/com/x/SecureIME.kt"
	layout := "app/src/main/res/layout/secure_keyboard.xml"
	root := imeRepo(t, map[string]string{"app/src/main/java/com/x/Main.kt": "package com.x\n\nclass Main\n"})
	reply := agent.TargetReply{
		Targets:  []agent.Target{{Path: manifestRel, Why: "declare it"}},
		NewFiles: []agent.Target{{Path: kt, Why: "the service"}},
	}
	s := nscSession(t, root, reply, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		switch req.Path {
		case kt:
			return agent.FixResult{Changed: true,
				PatchedContent: "package com.x\n\nclass SecureIME { val v = R.layout.secure_keyboard }\n"}, nil
		case manifestRel:
			return agent.FixResult{Changed: true, PatchedContent: manifestSvc}, nil
		case layout:
			require.True(t, req.Create)
			return agent.FixResult{Changed: true,
				PatchedContent: "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\" />\n"}, nil
		}
		return agent.FixResult{}, errors.New("unexpected fix call for " + req.Path)
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusFixed, out.Findings[0].Status, out.Findings[0].Detail)
	require.Contains(t, out.Findings[0].Detail, layout+" (completion)")
	require.NoError(t, s.work.restore())
}

// The manifest declares .SecureIME and no class exists: completion creates it
// in the module's language (Java here) and package.
func TestRun_CompletionCreatesAMissingComponentClass(t *testing.T) {
	root := imeRepo(t, map[string]string{"app/src/main/java/com/x/MainActivity.java": "package com.x;\n\npublic class MainActivity {}\n"})
	reply := agent.TargetReply{Targets: []agent.Target{{Path: manifestRel, Why: "declare it"}}}
	s := nscSession(t, root, reply, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		switch req.Path {
		case manifestRel:
			return agent.FixResult{Changed: true, PatchedContent: manifestSvc}, nil
		case imeClassRel:
			require.True(t, req.Create)
			require.Contains(t, req.Why, "com.x.SecureIME")
			return agent.FixResult{Changed: true, PatchedContent: imeClass}, nil
		}
		return agent.FixResult{}, errors.New("unexpected fix call for " + req.Path)
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusFixed, out.Findings[0].Status, out.Findings[0].Detail)
	require.Contains(t, out.Findings[0].Detail, imeClassRel+" (completion)")
	require.NoError(t, s.work.restore())
}

// The gateway budget runs out mid-completion: the unit rolls back and the run
// is truncated, as for any other fix call.
func TestRun_CompletionBudgetExhaustedRollsBack(t *testing.T) {
	root := imeRepo(t, map[string]string{imeClassRel: imeClass})
	s := nscSession(t, root, imeReply, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		switch req.Path {
		case imeConfigRel:
			return agent.FixResult{Changed: true, PatchedContent: imeConfigRef}, nil
		case manifestRel:
			return agent.FixResult{Changed: true, PatchedContent: manifestIME}, nil
		}
		return agent.FixResult{}, errors.New("429 session call budget exhausted")
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, out.Truncated)
	require.Empty(t, out.Patches)
	got, _ := readUnderRoot(root, manifestRel)
	require.Equal(t, manifestBody, got)
}

// Review Focus: the completion target is a file this same unit created. The
// rollback deletes it instead of failing on "content before the fix was not read".
func TestRun_CompletionOfAUnitCreatedFileRollsBackCleanly(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/build.gradle": imeGradle, manifestRel: manifestBody, imeClassRel: imeClass})
	reply := agent.TargetReply{
		Targets: []agent.Target{{Path: manifestRel, Why: "declare it"}},
		NewFiles: []agent.Target{{Path: imeConfigRel, Why: "config"},
			{Path: stringsRel, Why: "the app's strings"}},
	}
	s := nscSession(t, root, reply, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		switch {
		case req.Path == imeConfigRel && req.PriorViolation == "":
			return agent.FixResult{Changed: true, PatchedContent: imeConfigRef}, nil
		case req.Path == stringsRel && req.Create:
			return agent.FixResult{Changed: true, PatchedContent: stringsBody}, nil // lacks the string
		case req.Path == manifestRel:
			return agent.FixResult{Changed: true, PatchedContent: manifestIME}, nil
		}
		return agent.FixResult{}, nil
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusSkipped, out.Findings[0].Status, out.Findings[0].Detail)
	require.True(t, strings.Contains(out.Findings[0].Detail, "after 2 completion rounds"), out.Findings[0].Detail)
	_, statErr := os.Stat(filepath.Join(root, stringsRel))
	require.True(t, os.IsNotExist(statErr), "the unit created it, so the rollback deletes it")
}
