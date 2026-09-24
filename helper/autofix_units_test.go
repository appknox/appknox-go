package helper

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/stretchr/testify/require"
)

// targetsAt fakes a locate turn that answers with the given paths.
func targetsAt(paths ...string) func(context.Context, agent.Config, agent.TargetRequest) (agent.TargetReply, error) {
	return func(context.Context, agent.Config, agent.TargetRequest) (agent.TargetReply, error) {
		reply := agent.TargetReply{Targets: []agent.Target{}}
		for _, p := range paths {
			if p != "" {
				reply.Targets = append(reply.Targets, agent.Target{Path: p, Why: "test"})
			}
		}
		return reply, nil
	}
}

func dryAgentSession(root string, d autofixDeps, targets ...analysisTarget) fixSession {
	return fixSession{opts: AutofixOptions{FixMode: "agent", FileID: 1, DryRun: true},
		d: d, root: root, work: newWorkingTree(root), targets: targets}
}

const javaBody = "class A { void f() { Log.d(s); } }\n"

func TestRun_KnoxIQUnitLocatesOnceWithItsFullText(t *testing.T) {
	root := t.TempDir()
	var reqs []agent.TargetRequest
	d := autofixDeps{locateTargets: func(_ context.Context, _ agent.Config, req agent.TargetRequest) (agent.TargetReply, error) {
		reqs = append(reqs, req)
		return agent.TargetReply{}, nil
	}}
	s := dryAgentSession(root, d, analysisTarget{AnalysisID: 1, Inputs: FindingInputs{
		Finding: "Application Data Backup Allowed", VulnerabilityID: 3, Remediation: "r",
		Units: []FindingUnit{{Title: "allowBackup is true", Description: "d", Remediation: "set allowBackup=false"}},
	}})
	_, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, []agent.TargetRequest{{RepoRoot: root, VulnerabilityID: 3,
		Finding: "Application Data Backup Allowed", Title: "allowBackup is true",
		Description: "d", Remediation: "set allowBackup=false"}}, reqs)
}

// mfva's Application Logs: one analysis, three KnoxIQ findings, three files.
func TestRun_OneAnalysisThreeFindingsThreeFilesGivesThreeCalls(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"A": "app/src/main/java/com/x/A.java",
		"B": "app/src/main/java/com/x/B.java",
		"C": "app/src/main/java/com/x/C.java",
	}
	var units []FindingUnit
	for _, k := range []string{"A", "B", "C"} {
		writeSource(t, root, files[k], javaBody)
		units = append(units, FindingUnit{Title: "Logs in com.x." + k, Remediation: "remove the log in " + k})
	}
	var calls []agent.FixRequest
	d := autofixDeps{
		locateTargets: func(_ context.Context, _ agent.Config, req agent.TargetRequest) (agent.TargetReply, error) {
			k := strings.TrimPrefix(req.Title, "Logs in com.x.")
			return agent.TargetReply{Targets: []agent.Target{{Path: files[k], Why: "log in " + k}}}, nil
		},
		agentFix: func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
			calls = append(calls, req)
			return agent.FixResult{Changed: true, PatchedContent: "class A { void f() { } }\n"}, nil
		},
	}
	s := dryAgentSession(root, d, analysisTarget{AnalysisID: 1, Inputs: FindingInputs{
		Finding: "Application Logs", VulnerabilityID: 17, Remediation: "all", Units: units}})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Len(t, calls, 3)
	for i, k := range []string{"A", "B", "C"} {
		require.Equal(t, files[k], calls[i].Path)
		require.Equal(t, "remove the log in "+k, calls[i].Remediation,
			"each call carries only its own finding's remediation")
		require.Equal(t, "log in "+k, calls[i].Why)
		require.Empty(t, calls[i].OtherFiles)
	}
	require.Len(t, out.Patches, 3)
	require.Len(t, out.Findings, 3)
	for _, f := range out.Findings {
		require.Equal(t, statusFixed, f.Status)
		require.Equal(t, 17, f.VulnerabilityID)
	}
}

func TestRun_FansOutManifestThenResThenSource(t *testing.T) {
	root := t.TempDir()
	manifest := "app/src/main/AndroidManifest.xml"
	layout := "app/src/main/res/layout/activity_main.xml"
	src := "app/src/main/java/com/x/Main.java"
	writeSource(t, root, manifest, "<manifest><application/></manifest>\n")
	writeSource(t, root, layout, "<LinearLayout/>\n")
	writeSource(t, root, src, "class Main { }\n")
	var order []string
	var others [][]agent.Target
	d := autofixDeps{
		locateTargets: func(context.Context, agent.Config, agent.TargetRequest) (agent.TargetReply, error) {
			return agent.TargetReply{Targets: []agent.Target{
				{Path: src, Why: "isTaskRoot"}, {Path: layout, Why: "filterTouches"}, {Path: manifest, Why: "taskAffinity"},
			}}, nil
		},
		agentFix: func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
			order = append(order, req.Path)
			others = append(others, req.OtherFiles)
			return agent.FixResult{}, nil // decline: only the order is under test
		},
	}
	s := dryAgentSession(root, d, analysisTarget{AnalysisID: 1, Inputs: oneClass("StrandHogg", "r")})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{manifest, layout, src}, order)
	require.Equal(t, []agent.Target{{Path: layout, Why: "filterTouches"}, {Path: src, Why: "isTaskRoot"}}, others[0])
	require.Equal(t, statusSkipped, out.Findings[0].Status)
	require.Contains(t, out.Findings[0].Detail, manifest+" declined: no edit made")
}

func TestRun_OutcomeLinesCoverEveryStatus(t *testing.T) {
	root := t.TempDir()
	manifest := "app/src/main/AndroidManifest.xml"
	layout := "app/src/main/res/layout/activity_main.xml"
	src := "app/src/main/java/com/x/Main.java"
	writeSource(t, root, manifest, "<manifest><application/></manifest>\n")
	writeSource(t, root, layout, "<LinearLayout/>\n")
	writeSource(t, root, src, "class Main { }\n")
	writeSource(t, root, "app/build.gradle.kts", "plugins { }\n")

	replies := map[string]agent.TargetReply{
		"fixed":    {Targets: []agent.Target{{Path: manifest, Why: "exported=false"}}},
		"partial":  {Targets: []agent.Target{{Path: layout, Why: "filterTouches"}, {Path: src, Why: "guard"}}},
		"notfound": {Targets: []agent.Target{}, NotFound: []string{"android.util.Log: framework class"}},
		"build":    {Targets: []agent.Target{{Path: "app/build.gradle.kts", Why: "minify"}}},
	}
	var fixedRemediations []string
	d := autofixDeps{
		locateTargets: func(_ context.Context, _ agent.Config, req agent.TargetRequest) (agent.TargetReply, error) {
			if req.Title == "unparseable" {
				return agent.TargetReply{}, agent.ErrUnparseableReply
			}
			return replies[req.Title], nil
		},
		agentFix: func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
			fixedRemediations = append(fixedRemediations, req.Remediation)
			switch req.Path {
			case src:
				return agent.FixResult{}, nil
			case layout:
				return agent.FixResult{Changed: true, PatchedContent: "<LinearLayout><!-- fixed --></LinearLayout>\n"}, nil
			}
			return agent.FixResult{Changed: true, PatchedContent: "<manifest><application/><!-- fixed --></manifest>\n"}, nil
		},
	}
	units := []FindingUnit{}
	for _, title := range []string{"fixed", "partial", "notfound", "unparseable", "build"} {
		units = append(units, FindingUnit{Title: title, Remediation: "rem-" + title})
	}
	s := dryAgentSession(root, d,
		analysisTarget{AnalysisID: 1, Inputs: FindingInputs{Finding: "V", VulnerabilityID: 9, Remediation: "r", Units: units}},
		analysisTarget{AnalysisID: 2, Inputs: FindingInputs{Finding: "Hardcoded Secrets", VulnerabilityID: 120,
			SkipReason: "KnoxIQ: no findings"}},
	)
	out, err := s.run(context.Background())
	require.NoError(t, err)
	got := map[string]findingOutcome{}
	for i, title := range []string{"fixed", "partial", "notfound", "unparseable", "build", "skipAnalysis"} {
		got[title] = out.Findings[i]
	}
	require.Equal(t, statusFixed, got["fixed"].Status)
	require.Equal(t, statusPartial, got["partial"].Status)
	require.Equal(t, layout+" ok; "+src+" declined: no edit made", got["partial"].Detail)
	require.Equal(t, statusSkipped, got["notfound"].Status)
	require.Contains(t, got["notfound"].Detail, "android.util.Log")
	require.Equal(t, "locate: unparseable reply", got["unparseable"].Detail)
	require.Equal(t, "app/build.gradle.kts rejected: build file (not supported)", got["build"].Detail)
	require.Equal(t, findingOutcome{VulnerabilityID: 120, Finding: "Hardcoded Secrets",
		Status: statusSkipped, Detail: "KnoxIQ: no findings"}, got["skipAnalysis"])
	require.NotContains(t, fixedRemediations, "rem-notfound", "not_found only means no fix call")
	require.NotContains(t, fixedRemediations, "rem-build")
}

// TestRun_SkippedFindingsAreAppendedToOutcome is F1: a finding dropped inside
// a partly fixable analysis (third-party sibling, or no remediation text)
// still gets exactly one outcome line, carried on FindingInputs.Skipped and
// appended by run alongside the lines Units produces.
func TestRun_SkippedFindingsAreAppendedToOutcome(t *testing.T) {
	root, rel := repoWithFile(t, javaBody)
	d := autofixDeps{locateTargets: targetsAt(rel),
		agentFix: func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
			return agent.FixResult{Changed: true, PatchedContent: "class A { }\n"}, nil
		}}
	skip := findingOutcome{VulnerabilityID: 5, Finding: "Derived Crypto Keys",
		Title: "Vendored SDK class", Status: statusSkipped, Detail: "KnoxIQ: third-party code"}
	s := dryAgentSession(root, d, analysisTarget{AnalysisID: 1, Inputs: FindingInputs{
		Finding: "Derived Crypto Keys", VulnerabilityID: 5, Remediation: "r",
		Units:   []FindingUnit{{Title: "Fixable finding", Remediation: "fix it"}},
		Skipped: []findingOutcome{skip},
	}})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Len(t, out.Findings, 2, "one line for the fixed unit, one for the skipped sibling")
	require.Contains(t, out.Findings, skip)
}

// TestRun_BudgetExhaustionGivesNotAttemptedLineForEachRemainingUnit is F4's
// second half: when the gateway budget is exhausted, run breaks out of the
// whole target loop, so every unit it had not yet reached -- siblings of the
// unit that hit the exhaustion, and every unit of every later target -- got
// no outcome line at all. Each must now get its own SKIPPED line.
func TestRun_BudgetExhaustionGivesNotAttemptedLineForEachRemainingUnit(t *testing.T) {
	root, rel := repoWithFile(t, javaBody)
	d := autofixDeps{
		locateTargets: func(_ context.Context, _ agent.Config, req agent.TargetRequest) (agent.TargetReply, error) {
			if req.Title == "first" {
				return agent.TargetReply{Targets: []agent.Target{{Path: rel}}}, nil
			}
			return agent.TargetReply{}, errors.New("429 session call budget exhausted")
		},
		agentFix: func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
			return agent.FixResult{Changed: true, PatchedContent: "class A { }\n"}, nil
		},
	}
	s := dryAgentSession(root, d,
		analysisTarget{AnalysisID: 1, Inputs: FindingInputs{Finding: "V", VulnerabilityID: 9, Units: []FindingUnit{
			{Title: "first", Remediation: "fix a"},
			{Title: "second", Remediation: "fix b"}, // hits the exhaustion
			{Title: "third", Remediation: "fix c"},  // sibling never reached
		}}},
		analysisTarget{AnalysisID: 2, Inputs: FindingInputs{Finding: "W", VulnerabilityID: 10,
			Units: []FindingUnit{{Title: "fourth", Remediation: "fix d"}}}},
	)
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, out.Truncated)
	require.Len(t, out.Findings, 4, "first, second (locate failed), third and fourth (not attempted)")

	byTitle := map[string]findingOutcome{}
	for _, f := range out.Findings {
		byTitle[f.Title] = f
	}
	require.Equal(t, statusFixed, byTitle["first"].Status)
	require.Equal(t, statusSkipped, byTitle["third"].Status)
	require.Equal(t, "not attempted: gateway budget exhausted", byTitle["third"].Detail)
	require.Equal(t, 9, byTitle["third"].VulnerabilityID)
	require.Equal(t, statusSkipped, byTitle["fourth"].Status)
	require.Equal(t, "not attempted: gateway budget exhausted", byTitle["fourth"].Detail)
	require.Equal(t, 10, byTitle["fourth"].VulnerabilityID)
}

func TestRun_EveryCallFailingReturnsErrAllCallsFailed(t *testing.T) {
	root := t.TempDir()
	d := autofixDeps{locateTargets: func(context.Context, agent.Config, agent.TargetRequest) (agent.TargetReply, error) {
		return agent.TargetReply{}, errors.New("404 page not found")
	}}
	s := dryAgentSession(root, d,
		analysisTarget{AnalysisID: 1, Inputs: oneClass("f", "r")},
		analysisTarget{AnalysisID: 2, Inputs: oneClass("g", "r")})
	out, err := s.run(context.Background())
	require.ErrorIs(t, err, ErrAllCallsFailed)
	require.Len(t, out.Findings, 2, "the outcome lines survive the failure")
	_, fail := autofixExit(err)
	require.True(t, fail)
}

func TestRun_AllDeclinedExitsZero(t *testing.T) {
	root, rel := repoWithFile(t, javaBody)
	d := autofixDeps{
		locateTargets: targetsAt(rel),
		agentFix: func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
			return agent.FixResult{}, nil
		},
	}
	s := dryAgentSession(root, d, analysisTarget{AnalysisID: 1, Inputs: oneClass("f", "r")})
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.Equal(t, statusSkipped, out.Findings[0].Status)
}

func TestRun_LocateOnlyMakesNoFixCallsAndNoDelivery(t *testing.T) {
	root, rel := repoWithFile(t, javaBody)
	fixed := false
	d := autofixDeps{
		locateTargets: func(context.Context, agent.Config, agent.TargetRequest) (agent.TargetReply, error) {
			return agent.TargetReply{
				Targets:  []agent.Target{{Path: rel, Why: "weak PRNG here"}, {Path: "app/build.gradle"}},
				NotFound: []string{"java.util.Random: framework"},
			}, nil
		},
		agentFix: func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
			fixed = true
			return agent.FixResult{Changed: true, PatchedContent: "x"}, nil
		},
		deliver: func(context.Context, AutofixOptions, []filePatch) (Delivery, error) {
			t.Fatal("locate-only must not deliver")
			return Delivery{}, nil
		},
	}
	s := fixSession{opts: AutofixOptions{FixMode: "agent", FileID: 1, LocateOnly: true},
		d: d, root: root, work: newWorkingTree(root),
		targets: []analysisTarget{{AnalysisID: 1, Inputs: oneClass("Weak PRNG", "use SecureRandom")}}}
	out, err := s.run(context.Background())
	require.NoError(t, err)
	require.False(t, fixed)
	require.Empty(t, out.Patches)
	require.Equal(t, []string{rel}, out.Located)
	require.Equal(t, statusTargets, out.Findings[0].Status)
	require.Equal(t, rel+" (weak PRNG here); app/build.gradle rejected: invalid path; "+
		"not found in repo: java.util.Random: framework (likely third-party)", out.Findings[0].Detail)
}
