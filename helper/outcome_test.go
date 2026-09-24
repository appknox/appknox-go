package helper

import (
	"errors"
	"strings"
	"testing"

	"github.com/appknox/appknox-go/agent"
	"github.com/stretchr/testify/require"
)

const (
	manifestPath = "app/src/main/AndroidManifest.xml"
	entrancePath = "app/src/main/java/com/x/EntranceActivity.java"
)

func TestSummarizeFinding_Fixed(t *testing.T) {
	o := summarizeFinding(40, "Unprotected Exported Service",
		[]targetResult{{Path: manifestPath, Patched: true}}, nil)
	require.Equal(t, findingOutcome{VulnerabilityID: 40, Finding: "Unprotected Exported Service",
		Status: statusFixed, Detail: manifestPath}, o)
}

func TestSummarizeFinding_Partial(t *testing.T) {
	o := summarizeFinding(118, "StrandHogg", []targetResult{
		{Path: manifestPath, Patched: true},
		{Path: entrancePath, Reason: reasonDeclined},
	}, nil)
	require.Equal(t, statusPartial, o.Status)
	require.Equal(t, manifestPath+" ok; "+entrancePath+" declined: no edit made", o.Detail)
}

func TestSummarizeFinding_RejectedTargetMakesPartial(t *testing.T) {
	o := summarizeFinding(104, "Obfuscation", append(
		[]targetResult{{Path: manifestPath, Patched: true}},
		rejectionResults([]rejection{{Path: "app/build.gradle", Reason: reasonBuildFile}})...), nil)
	require.Equal(t, statusPartial, o.Status)
	require.Contains(t, o.Detail, "app/build.gradle rejected: build file (not supported)")
}

func TestSummarizeFinding_SkippedNotFound(t *testing.T) {
	o := summarizeFinding(17, "Application Logs", nil,
		notFoundNotes([]string{"android.util.Log: framework class"}))
	require.Equal(t, statusSkipped, o.Status)
	require.Equal(t, "not found in repo: android.util.Log: framework class (likely third-party)", o.Detail)
}

func TestSummarizeFinding_SkippedNothing(t *testing.T) {
	o := summarizeFinding(0, "x", nil, nil)
	require.Equal(t, statusSkipped, o.Status)
	require.Equal(t, "locate: no targets", o.Detail)
}

func TestSummarizeFinding_NotFoundDoesNotDowngradeFixed(t *testing.T) {
	o := summarizeFinding(121, "Tapjacking", []targetResult{{Path: manifestPath, Patched: true}},
		notFoundNotes([]string{"LinearLayout: framework widget"}))
	require.Equal(t, statusFixed, o.Status)
	require.Equal(t, manifestPath+"; not found in repo: LinearLayout: framework widget (likely third-party)", o.Detail)
}

func TestLocatedOutcome(t *testing.T) {
	o := locatedOutcome(FindingInputs{VulnerabilityID: 127, Finding: "Weak PRNG"},
		[]agent.Target{{Path: "a/A.java", Why: "Random here"}},
		rejectionResults([]rejection{{Path: "b.gradle", Reason: reasonInvalidPath}}),
		notFoundNotes([]string{"java.util.Random: framework"}))
	require.Equal(t, statusTargets, o.Status)
	require.Equal(t, "a/A.java (Random here); b.gradle rejected: invalid path; "+
		"not found in repo: java.util.Random: framework (likely third-party)", o.Detail)
	require.Equal(t, "locate: no targets", locatedOutcome(FindingInputs{}, nil, nil, nil).Detail)
}

func TestSkippedAnalysis(t *testing.T) {
	o := skippedAnalysis(7, FindingInputs{Finding: "SSL Pinning", VulnerabilityID: 83,
		SkipReason: "KnoxIQ: third-party code"})
	require.Equal(t, findingOutcome{VulnerabilityID: 83, Finding: "SSL Pinning",
		Status: statusSkipped, Detail: "KnoxIQ: third-party code"}, o)
	o = skippedAnalysis(7, FindingInputs{})
	require.Equal(t, "analysis 7", o.Finding)
	require.Equal(t, "KnoxIQ: nothing fixable", o.Detail)
}

func TestFormatOutcomeLine(t *testing.T) {
	line := formatOutcomeLine(findingOutcome{VulnerabilityID: 40,
		Finding: "Unprotected Exported Service", Status: statusFixed, Detail: manifestPath})
	require.True(t, strings.HasPrefix(line, "FIXED    40   Unprotected Exported Service "), line)
	require.True(t, strings.HasSuffix(line, " "+manifestPath), line)
	require.True(t, strings.HasPrefix(
		formatOutcomeLine(findingOutcome{Finding: "x", Status: statusSkipped, Detail: "d"}),
		"SKIPPED  -    x"))
}

func TestCallTally(t *testing.T) {
	var c callTally
	require.False(t, c.allFailed(), "no calls is not all-failed")
	c.record(errors.New("404 page not found"))
	require.True(t, c.allFailed())
	c.record(nil)
	require.False(t, c.allFailed())

	var u callTally
	u.record(agent.ErrUnparseableReply)
	require.False(t, u.allFailed(), "an unparseable reply is an answer, not a transport failure")

	var b callTally
	b.record(errors.New("429 session call budget exhausted"))
	require.False(t, b.allFailed(), "budget exhaustion truncates the run; it is not counted here")
	require.Equal(t, 0, b.calls)

	var none *callTally
	require.NotPanics(t, func() { none.record(errors.New("x")) })
}
