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

// mfvaGradle is mfva's app/build.gradle, trimmed to the parts KnoxIQ touches.
const mfvaGradle = `apply plugin: 'com.android.application'

android {
    buildTypes {
        release {
            minifyEnabled false
        }
    }
}
dependencies {
    api 'com.squareup.okhttp3:okhttp:3.8.0'
    api 'redis.clients:jedis:2.9.0'
    testImplementation 'junit:junit:4.12'
}
`

const (
	exportedRel     = "app/src/main/java/com/appknox/mfva/ExportedActivity.java"
	exportedJedis   = "import redis.clients.jedis.Jedis;\nclass ExportedActivity { void f() { Jedis j = new Jedis(\"localhost\"); } }\n"
	exportedNoJedis = "class ExportedActivity { void f() { } }\n"
	jedisLine       = "    api 'redis.clients:jedis:2.9.0'\n"
)

func withoutJedis() string { return strings.Replace(mfvaGradle, jedisLine, "", 1) }

func TestIsModuleBuildScript(t *testing.T) {
	for p, want := range map[string]bool{
		"app/build.gradle":       true,
		"app/build.gradle.kts":   true,
		"lib/core/build.gradle":  true,
		"build.gradle":           false, // the root script
		"settings.gradle":        false,
		"app/proguard-rules.pro": false,
		"app/mybuild.gradle":     false,
	} {
		require.Equal(t, want, isModuleBuildScript(p), p)
	}
}

// KnoxIQ's own examples for mfva file 83: every one of these is in a real
// remediation and would break or widen the build if shipped.
func TestCheckBuildScriptEdit_RefusesAdditions(t *testing.T) {
	cases := map[string]string{
		"117 signing config":    "        signingConfig signingConfigs.release\n",
		"117 keystore from env": "        storeFile file(System.getenv(\"KEYSTORE_PATH\"))\n",
		"37 retrofit":           "    implementation(\"com.squareup.retrofit2:retrofit:2.9.0\")\n",
		"test dependency":       "    testImplementation 'org.mockito:mockito-core:5.0.0'\n",
		"plugin":                "apply plugin: 'kotlin-android'\n",
		"repository":            "repositories { mavenCentral() }\n",
	}
	for name, added := range cases {
		v := checkBuildScriptEdit("app/build.gradle", mfvaGradle, mfvaGradle+added)
		require.NotNil(t, v, name)
		require.Equal(t, "build-script-addition", v.Rule, name)
	}
}

func TestCheckBuildScriptEdit_AllowsSettingsAndRemovals(t *testing.T) {
	patched := strings.Replace(withoutJedis(), "minifyEnabled false\n",
		"minifyEnabled true\n            shrinkResources true\n            debuggable false\n", 1)
	require.Nil(t, checkBuildScriptEdit("app/build.gradle", mfvaGradle, patched))
	require.Nil(t, checkBuildScriptEdit("app/build.gradle", mfvaGradle,
		mfvaGradle+"android { targetSdkVersion 34 }\n"))
	// Not a module script: not this check's business.
	require.Nil(t, checkBuildScriptEdit("app/src/main/java/A.java", "", "implementation 'a.b:c:1'\n"))
}

func TestRemovedDependencyLines(t *testing.T) {
	require.Equal(t, []string{jedisLine[:len(jedisLine)-1]}, removedDependencyLines(mfvaGradle, withoutJedis()))
	commented := strings.Replace(mfvaGradle, "    api 'redis.clients", "    // api 'redis.clients", 1)
	require.Len(t, removedDependencyLines(mfvaGradle, commented), 1)
	require.Empty(t, removedDependencyLines(mfvaGradle, mfvaGradle))
	// A sibling artifact of the same group does not hide the removal.
	two := "dependencies {\n    implementation 'com.squareup.retrofit2:retrofit:2.9.0'\n" +
		"    implementation 'com.squareup.retrofit2:converter-gson:2.9.0'\n}\n"
	one := strings.Replace(two, "    implementation 'com.squareup.retrofit2:converter-gson:2.9.0'\n", "", 1)
	require.Len(t, removedDependencyLines(two, one), 1)
}

// Review findings: forms of adding a dependency that a line-start match missed,
// and a configuration block that is not a dependency.
func TestDependencyLineRE(t *testing.T) {
	for _, line := range []string{
		"dependencies { implementation 'a.b:c:1' }",
		`    add("implementation", "a.b:c:1")`,
		`    "implementation"("a.b:c:1")`,
		"    lintChecks project(':x')",
		"    implementation(libs.foo)",
		"    wearApp project(':wear')",
		"    implementation group: 'a.b', name: 'c', version: '1'",
	} {
		require.True(t, dependencyLineRE.MatchString(line), line)
	}
	for _, line := range []string{
		"    compileSdkVersion 34",
		"    kapt {",
		"    minifyEnabled true",
		"    targetSdkVersion 26",
		`    versionName "1.1.1"`,
	} {
		require.False(t, dependencyLineRE.MatchString(line), line)
	}
}

func TestCheckBuildScriptEdit_InlineBlockCommentDoesNotHideAnAddition(t *testing.T) {
	v := checkBuildScriptEdit("app/build.gradle", mfvaGradle, mfvaGradle+"/* x */ implementation 'a.b:c:1'\n")
	require.NotNil(t, v)
}

func TestCheckRemovedDependency_UnresolvableNotationIsRefused(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/build.gradle": "x\n"})
	for _, line := range []string{"    implementation(libs.jedis)\n", "    implementation project(':core')\n"} {
		orig := "dependencies {\n" + line + "}\n"
		v := checkRemovedDependency(root, "app/build.gradle", orig, "dependencies {\n}\n")
		require.NotNil(t, v, line)
		require.Equal(t, "dependency-unresolved", v.Rule, line)
	}
	// Map notation resolves.
	orig := "dependencies {\n    implementation group: 'redis.clients', name: 'jedis', version: '2.9.0'\n}\n"
	require.Nil(t, checkRemovedDependency(root, "app/build.gradle", orig, "dependencies {\n}\n"))
}

func TestEditableBuildScript(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle":          "x",
		"android/build.gradle":      "x", // root of a nested Flutter / RN project
		"android/settings.gradle":   "x",
		"android/app/build.gradle":  "x",
		"buildSrc/build.gradle.kts": "x",
		"lib/buildSrc/build.gradle": "x",
	})
	require.True(t, editableBuildScript(root, "app/build.gradle"))
	require.True(t, editableBuildScript(root, "android/app/build.gradle"))
	require.False(t, editableBuildScript(root, "android/build.gradle"))
	require.False(t, editableBuildScript(root, "buildSrc/build.gradle.kts"))
	require.False(t, editableBuildScript(root, "lib/buildSrc/build.gradle"))
}

func TestCheckRemovedDependency_RefusedWhileSourceStillUsesIt(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/build.gradle": mfvaGradle, exportedRel: exportedJedis})
	v := checkRemovedDependency(root, "app/build.gradle", mfvaGradle, withoutJedis())
	require.NotNil(t, v)
	require.Equal(t, "dependency-still-used", v.Rule)
	require.Contains(t, v.Detail, exportedRel)
}

func TestFirstSourceReferencing_DoesNotFollowSymlinks(t *testing.T) {
	outside := writeRepo(t, map[string]string{"Use.java": "import redis.clients.jedis.Jedis;\n"})
	root := writeRepo(t, map[string]string{"app/src/A.java": "class A {}\n"})
	require.NoError(t, os.Symlink(filepath.Join(outside, "Use.java"), filepath.Join(root, "app/src/Link.java")))
	require.Equal(t, "", firstSourceReferencing(root, "redis.clients"))
}

func TestCheckRemovedDependency_AllowedOnceSourceIsClean(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app/build.gradle": mfvaGradle,
		exportedRel:        exportedNoJedis,
		// A string or comment naming the package is not a use.
		"app/src/main/java/com/appknox/mfva/Notes.java": "// redis.clients.jedis was here\nclass N { String s = \"redis.clients.x\"; }\n",
		// Build output is not the app's source.
		"app/build/generated/G.java": "import redis.clients.jedis.Jedis;\n",
	})
	require.Nil(t, checkRemovedDependency(root, "app/build.gradle", mfvaGradle, withoutJedis()))
}

// jedisSession is mfva 37: KnoxIQ marks jedis third-party and the locate agent
// names app/build.gradle and ExportedActivity.java.
func jedisSession(root string, fix func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error)) fixSession {
	d := autofixDeps{locateTargets: targetsAt("app/build.gradle", exportedRel), agentFix: fix}
	return dryAgentSession(root, d, analysisTarget{AnalysisID: 1, Inputs: FindingInputs{
		Finding: "Redis library", VulnerabilityID: 37, Remediation: "r",
		Units: []FindingUnit{{Title: "jedis", Remediation: "remove jedis", ThirdParty: true}},
	}})
}

// The Java fix runs first, and the dependency removal passes the gate because
// no source uses jedis any more.
func TestRun_ThirdPartyDependencyRemovedWithItsUse(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/build.gradle": mfvaGradle, exportedRel: exportedJedis})
	var order []string
	s := jedisSession(root, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		order = append(order, req.Path)
		if req.Path == exportedRel {
			return agent.FixResult{Changed: true, PatchedContent: exportedNoJedis}, nil
		}
		return agent.FixResult{Changed: true, PatchedContent: withoutJedis()}, nil
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{exportedRel, "app/build.gradle"}, order, "source first, build script last")
	require.Equal(t, statusFixed, out.Findings[0].Status, out.Findings[0].Detail)
	require.Len(t, out.Patches, 2)
}

// The Java fixer declines: the dependency must stay, or the build breaks.
func TestRun_DependencyKeptWhenItsUseWasNotRemoved(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/build.gradle": mfvaGradle, exportedRel: exportedJedis})
	s := jedisSession(root, func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
		if req.Path == exportedRel {
			return agent.FixResult{}, nil
		}
		return agent.FixResult{Changed: true, PatchedContent: withoutJedis()}, nil
	})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusSkipped, out.Findings[0].Status)
	require.Contains(t, out.Findings[0].Detail, "rejected by patch gate (dependency-still-used)")
	require.Empty(t, out.Patches)
}

// The backstop: okhttp's group (com.squareup.okhttp3) is not its package
// (okhttp3), so checkRemovedDependency cannot see the use. The source fix is
// refused by the gate, the build-script edit lands, and the unit is rolled
// back so nothing half-applied ships.
func TestRun_BuildScriptUnitRolledBackWhenAnotherTargetFails(t *testing.T) {
	const src = "app/src/main/java/com/x/Net.java"
	root := writeRepo(t, map[string]string{"app/build.gradle": mfvaGradle, src: "class Net { void f() { } }\n"})
	patchedGradle := strings.Replace(mfvaGradle, "    api 'com.squareup.okhttp3:okhttp:3.8.0'\n", "", 1)
	d := autofixDeps{
		locateTargets: targetsAt(src, "app/build.gradle"),
		agentFix: func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
			if req.Path == src {
				return agent.FixResult{Changed: true, PatchedContent: "class Net { void f() { \n"}, nil // unbalanced
			}
			return agent.FixResult{Changed: true, PatchedContent: patchedGradle}, nil
		},
	}
	s := dryAgentSession(root, d, analysisTarget{AnalysisID: 1, Inputs: FindingInputs{
		Finding: "OkHttp", VulnerabilityID: 7, Remediation: "r",
		Units: []FindingUnit{{Title: "okhttp", Remediation: "remove okhttp", ThirdParty: true}},
	}})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusSkipped, out.Findings[0].Status, out.Findings[0].Detail)
	require.Contains(t, out.Findings[0].Detail, reasonRolledBack)
	require.Empty(t, out.Patches)
	got, err := readUnderRoot(root, "app/build.gradle")
	require.NoError(t, err)
	require.Equal(t, mfvaGradle, got, "the build script is back as it was")
}

// Review finding: a run that stops mid-unit (here the manual path, where any
// fix error is fatal) still rolls the unit back before returning.
func TestRun_RollbackAlsoOnEarlyReturn(t *testing.T) {
	root := writeRepo(t, map[string]string{"app/build.gradle": mfvaGradle, "lib/build.gradle": mfvaGradle})
	d := autofixDeps{
		locateTargets: targetsAt("app/build.gradle", "lib/build.gradle"),
		agentFix: func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
			if req.Path == "lib/build.gradle" {
				return agent.FixResult{}, errors.New("gateway down")
			}
			return agent.FixResult{Changed: true, PatchedContent: withoutJedis()}, nil
		},
	}
	s := dryAgentSession(root, d)
	s.opts.FileID = 0
	res, err := s.runUnit(context.Background(), FindingInputs{Finding: "Redis library"},
		FindingUnit{Title: "jedis", Remediation: "remove jedis"})
	require.Error(t, err)
	require.Empty(t, res.patches)
	require.Contains(t, res.outcome.Detail, reasonRolledBack)
	got, readErr := readUnderRoot(root, "app/build.gradle")
	require.NoError(t, readErr)
	require.Equal(t, mfvaGradle, got)
}

// A declined target does not roll back: 3 (debuggable) locates a manifest
// that has no debuggable attribute; only the build script needs the change.
func TestRun_DeclinedTargetDoesNotRollBackBuildScript(t *testing.T) {
	const manifest = "app/src/main/AndroidManifest.xml"
	root := writeRepo(t, map[string]string{"app/build.gradle": mfvaGradle, manifest: "<manifest><application/></manifest>\n"})
	patchedGradle := strings.Replace(mfvaGradle, "minifyEnabled false\n",
		"minifyEnabled false\n            debuggable false\n", 1)
	d := autofixDeps{
		locateTargets: targetsAt(manifest, "app/build.gradle"),
		agentFix: func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
			if req.Path == manifest {
				return agent.FixResult{}, nil
			}
			return agent.FixResult{Changed: true, PatchedContent: patchedGradle}, nil
		},
	}
	s := dryAgentSession(root, d, analysisTarget{AnalysisID: 1, Inputs: FindingInputs{
		Finding: "Debug enabled", VulnerabilityID: 3, Remediation: "r",
		Units: []FindingUnit{{Title: "debuggable", Remediation: "debuggable false"}},
	}})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusPartial, out.Findings[0].Status, out.Findings[0].Detail)
	require.Len(t, out.Patches, 1)
	require.Equal(t, "app/build.gradle", out.Patches[0].Path)
}

// Third-party with nothing in this repository to change: skipped with the
// reason, and the locate turn was told the finding is third-party.
func TestRun_ThirdPartyWithNoSourceIsSkipped(t *testing.T) {
	var sawThirdParty bool
	d := autofixDeps{
		locateTargets: func(_ context.Context, _ agent.Config, req agent.TargetRequest) (agent.TargetReply, error) {
			sawThirdParty = req.ThirdParty
			return agent.TargetReply{Targets: []agent.Target{},
				NotFound: []string{"com.vendor.Sdk: library class"}}, nil
		},
	}
	s := dryAgentSession(t.TempDir(), d, analysisTarget{AnalysisID: 1, Inputs: FindingInputs{
		Finding: "Vendored SDK", VulnerabilityID: 5, Remediation: "r",
		Units: []FindingUnit{{Title: "sdk", Remediation: "patch the sdk", ThirdParty: true}},
	}})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.True(t, sawThirdParty, "the locate turn is told the finding is third-party")
	require.Equal(t, statusSkipped, out.Findings[0].Status)
	require.Contains(t, out.Findings[0].Detail, reasonThirdPartyNoSource)
}

// Review bypass: the blocklist missed script plugins and code that runs at
// Gradle configuration time. Added lines are now held to an allowlist of the
// settings a remediation changes.
func TestCheckBuildScriptEdit_RefusesCodeAndScriptPlugins(t *testing.T) {
	for name, added := range map[string]string{
		"apply from":          "apply from: 'https://example.com/x.gradle'\n",
		"kts apply from":      "apply(from = \"x.gradle.kts\")\n",
		"execute":             "\"sh -c id\".execute()\n",
		"exec task":           "tasks.register('x') { exec { commandLine 'sh', '-c', 'id' } }\n",
		"buildscript":         "buildscript { }\n",
		"setting then code":   "android { buildTypes { release { debuggable false; println 'x' } } }\n",
		"url in proguard":     "android { buildTypes { release { proguardFiles 'https://x/y.pro' } } }\n",
		"slashes in a string": "android { debuggable \"//\"; evil() }\n",
	} {
		require.NotNil(t, checkBuildScriptEdit("app/build.gradle", mfvaGradle, mfvaGradle+added), name)
	}
}

func TestCheckBuildScriptEdit_AllowsRemediationSettings(t *testing.T) {
	for _, added := range []string{
		"android {\n    buildTypes {\n        release {\n            minifyEnabled true\n            shrinkResources true\n            debuggable false\n            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'\n        }\n    }\n}\n",
		"android { defaultConfig { targetSdkVersion 34 } }\n",
		"android {\n    buildTypes {\n        getByName(\"release\") {\n            isMinifyEnabled = true\n            isDebuggable = false\n            proguardFiles(getDefaultProguardFile(\"proguard-android-optimize.txt\"), \"proguard-rules.pro\")\n        }\n    }\n}\n",
		"android { buildTypes { release { debuggable false } } } // strip debug\n",
	} {
		require.Nil(t, checkBuildScriptEdit("app/build.gradle", mfvaGradle, mfvaGradle+added), added)
	}
}

// Re-review bypasses: comment stripping ran before the allowlist and knew
// nothing of strings, so /* */ inside quotes, a line starting with *, or an
// unclosed paren joined to a *-line hid code from it.
func TestCheckBuildScriptEdit_RefusesCommentAndParenTricks(t *testing.T) {
	for name, added := range map[string]string{
		"comment markers in strings": "android { release { proguardFiles 'a/*', \"${'id'.execute().text}\", '*/b' } }\n",
		"star line after open":       "/*\n*/ 'id'.execute()\n",
		"unclosed paren":             "android { release { proguardFiles('a'\n* 'id'.execute().hashCode())\n} }\n",
		"dollar":                     "android { release { minifyEnabled true } }\n$x\n",
	} {
		require.NotNil(t, checkBuildScriptEdit("app/build.gradle", mfvaGradle, mfvaGradle+added), name)
	}
}

// Legitimate remediation shapes the first allowlist refused.
func TestCheckBuildScriptEdit_AllowsSdkAndCreateForms(t *testing.T) {
	for _, added := range []string{
		"android { compileSdkVersion 34 }\n",
		"android { compileSdk = 34 }\n",
		"android { defaultConfig { targetSdkVersion(34); minSdkVersion(24) } }\n",
		"android { buildTypes { create(\"release\") { isMinifyEnabled = true } } }\n",
		"// release hardening\n",
	} {
		require.Nil(t, checkBuildScriptEdit("app/build.gradle", mfvaGradle, mfvaGradle+added), added)
	}
}

// Round-3 bypass: deleting a block comment's markers switches on whatever it
// held, with no line added. Removals are held to the same kinds of line an
// edit may add, plus dependency lines and // comments.
func TestCheckBuildScriptEdit_RefusesActivationByDeletion(t *testing.T) {
	commented := mfvaGradle + "/*\ntasks.register(\"x\") { doLast { \"id\".execute() } }\n*/\n"
	activated := mfvaGradle + "tasks.register(\"x\") { doLast { \"id\".execute() } }\n"
	require.NotNil(t, checkBuildScriptEdit("app/build.gradle", commented, activated))

	// Removing a task outright is not a remediation either.
	require.NotNil(t, checkBuildScriptEdit("app/build.gradle", activated, mfvaGradle))
	// A dependency line joined to other code is not a plain removal.
	guarded := mfvaGradle + "dependencies { api 'a.b:c:1' }; if (false) {\n\"id\".execute()\n}\n"
	require.NotNil(t, checkBuildScriptEdit("app/build.gradle", guarded,
		mfvaGradle+"\"id\".execute()\n"))
	// Moving release's closing brace below debug { } re-nests it.
	nested := "android {\n    buildTypes {\n        release {\n            minifyEnabled false\n        }\n" +
		"        debug {\n            debuggable true\n        }\n    }\n}\n"
	renested := "android {\n    buildTypes {\n        release {\n            minifyEnabled false\n" +
		"        debug {\n            debuggable true\n        }\n        }\n    }\n}\n"
	require.NotNil(t, checkBuildScriptEdit("app/build.gradle", nested, renested))
	// Removing a // comment line is harmless.
	require.Nil(t, checkBuildScriptEdit("app/build.gradle", mfvaGradle+"// old note\n", mfvaGradle))
}
