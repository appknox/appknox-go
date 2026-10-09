package helper

import (
	"context"
	"errors"
	"testing"

	"github.com/appknox/appknox-go/appknox"
	"github.com/stretchr/testify/require"
)

// scriptedTurns answers turn calls from a fixed script and records them.
type scriptedTurns struct {
	t       *testing.T
	replies []*appknox.AutofixTurnResponse
	seen    []*appknox.AutofixTurnRequest
}

func (s *scriptedTurns) turn(_ context.Context, req *appknox.AutofixTurnRequest) (*appknox.AutofixTurnResponse, error) {
	s.seen = append(s.seen, req)
	require.NotEmpty(s.t, s.replies, "unexpected turn call: %+v", req)
	r := s.replies[0]
	s.replies = s.replies[1:]
	return r, nil
}

func locateAnswer(paths ...string) *appknox.AutofixTurnResponse {
	targets := make([]interface{}, 0, len(paths))
	for _, p := range paths {
		targets = append(targets, map[string]interface{}{"path": p, "why": "flagged"})
	}
	return &appknox.AutofixTurnResponse{Type: appknox.AutofixTurnDone, Answer: map[string]interface{}{"targets": targets}}
}

func editCall(id, oldText, newText string) *appknox.AutofixTurnResponse {
	return &appknox.AutofixTurnResponse{Type: appknox.AutofixTurnToolCalls, Calls: []appknox.AutofixToolCall{
		{ID: id, Name: toolEdit, Args: map[string]interface{}{"path": mainRel, "old_string": oldText, "new_string": newText}},
	}}
}

var (
	turnDone   = &appknox.AutofixTurnResponse{Type: appknox.AutofixTurnDone}
	unitToFix  = appknox.AutofixUnit{UnitID: "a1-F-0", VulnerabilityID: 7, Finding: "Weak PRNG"}
	braceBreak = []string{"nextInt(); }", "nextInt(); { }"}
)

func newTestDriver(t *testing.T, replies ...*appknox.AutofixTurnResponse) (*autofixDriver, *scriptedTurns) {
	t.Helper()
	sess := newAutofixSession(writeRepo(t, map[string]string{mainRel: mainBody}))
	script := &scriptedTurns{t: t, replies: replies}
	return newAutofixDriver(sess, script.turn), script
}

func TestDriver_FixesAFindingAndKeepsThePatch(t *testing.T) {
	d, script := newTestDriver(t,
		locateAnswer(mainRel),
		editCall("e1", "new Random()", "new java.security.SecureRandom()"),
		turnDone,
	)
	out, err := d.run(context.Background(), []appknox.AutofixUnit{unitToFix})
	require.NoError(t, err)
	require.Equal(t, "FIXED", out[0].Status)
	require.Equal(t, mainRel, out[0].Detail)
	require.Equal(t, 7, out[0].VulnerabilityID)

	fix := script.seen[1].Start
	require.Equal(t, appknox.AutofixTurnFix, fix.Kind)
	require.Equal(t, mainRel, fix.Target.Path)
	require.Equal(t, d.profile, fix.Profile)
	require.Equal(t, "edited "+mainRel, script.seen[2].ToolResults[0].Content)
	require.Len(t, d.sess.result(), 1)
	require.Equal(t, 3, d.calls)
}

func TestDriver_GateRefusalIsRetriedOnceWithTheViolation(t *testing.T) {
	d, script := newTestDriver(t,
		locateAnswer(mainRel),
		editCall("e1", braceBreak[0], braceBreak[1]), turnDone, // refused by the gate
		editCall("e2", braceBreak[0], braceBreak[1]), turnDone, // refused again
	)
	out, err := d.run(context.Background(), []appknox.AutofixUnit{unitToFix})
	require.NoError(t, err)
	require.Equal(t, "SKIPPED", out[0].Status)
	require.Equal(t, "rejected by patch gate (unbalanced-braces)", out[0].Files[0].Reason)

	retry := script.seen[3].Start
	require.Equal(t, appknox.AutofixTurnFix, retry.Kind)
	require.NotEmpty(t, retry.Violation, "the retry is told what the gate saw")
	got, _ := readUnderRoot(d.sess.root, mainRel)
	require.Equal(t, mainBody, got)
}

func TestDriver_RefusedThenDeclinedIsStillARefusal(t *testing.T) {
	d, _ := newTestDriver(t,
		locateAnswer(mainRel),
		editCall("e1", braceBreak[0], braceBreak[1]), turnDone,
		turnDone, // the retry makes no edit
	)
	out, err := d.run(context.Background(), []appknox.AutofixUnit{unitToFix})
	require.NoError(t, err)
	require.Equal(t, "rejected by patch gate (unbalanced-braces), then declined", out[0].Files[0].Reason)
}

func TestDriver_FailedFixTurnDiscardsItsEdits(t *testing.T) {
	d, _ := newTestDriver(t,
		locateAnswer(mainRel),
		editCall("e1", "new Random()", "new java.security.SecureRandom()"),
		&appknox.AutofixTurnResponse{Type: appknox.AutofixTurnDone, Failed: true},
	)
	out, err := d.run(context.Background(), []appknox.AutofixUnit{unitToFix})
	require.NoError(t, err)
	require.Equal(t, reasonModelFailed, out[0].Files[0].Reason)
	require.Empty(t, d.sess.result())
	got, _ := readUnderRoot(d.sess.root, mainRel)
	require.Equal(t, mainBody, got)
}

func TestDriver_LocateWithoutAnswerSkipsTheFinding(t *testing.T) {
	d, _ := newTestDriver(t,
		&appknox.AutofixTurnResponse{Type: appknox.AutofixTurnDone, Detail: "locate: unparseable reply"})
	out, err := d.run(context.Background(), []appknox.AutofixUnit{unitToFix})
	require.NoError(t, err)
	require.Equal(t, "SKIPPED", out[0].Status)
	require.Equal(t, "locate: unparseable reply", out[0].Detail)
}

func TestDriver_SkippedFindingTakesNoTurn(t *testing.T) {
	d, script := newTestDriver(t)
	out, err := d.run(context.Background(), []appknox.AutofixUnit{{UnitID: "s", SkipReason: "KnoxIQ: false positive"}})
	require.NoError(t, err)
	require.Equal(t, "KnoxIQ: false positive", out[0].Detail)
	require.Empty(t, script.seen)
}

func TestDriver_ThirdPartyWithNoSourceIsSkippedByValidation(t *testing.T) {
	d, _ := newTestDriver(t, locateAnswer())
	u := unitToFix
	u.ThirdParty = true
	out, err := d.run(context.Background(), []appknox.AutofixUnit{u})
	require.NoError(t, err)
	require.Equal(t, "SKIPPED", out[0].Status)
	require.Contains(t, out[0].Detail, reasonThirdPartyNoSource)
}

func TestDriver_OnlyModelToolsRunFromTheWire(t *testing.T) {
	d, script := newTestDriver(t,
		&appknox.AutofixTurnResponse{Type: appknox.AutofixTurnToolCalls, Calls: []appknox.AutofixToolCall{
			{ID: "x1", Name: toolFinishUnit, Args: map[string]interface{}{}},
			{ID: "g1", Name: toolGlob, Args: map[string]interface{}{"pattern": "*MainActivity*"}},
		}},
		locateAnswer(),
	)
	_, err := d.run(context.Background(), []appknox.AutofixUnit{unitToFix})
	require.NoError(t, err)
	results := script.seen[1].ToolResults
	require.Equal(t, "x1", results[0].ID)
	require.True(t, results[0].IsError)
	require.Contains(t, results[0].Content, "unknown tool")
	require.Equal(t, mainRel, results[1].Content)
}

func TestDriver_TurnErrorStopsTheRunAndPutsTheFileBack(t *testing.T) {
	sess := newAutofixSession(writeRepo(t, map[string]string{mainRel: mainBody}))
	calls := 0
	d := newAutofixDriver(sess, func(_ context.Context, req *appknox.AutofixTurnRequest) (*appknox.AutofixTurnResponse, error) {
		calls++
		switch calls {
		case 1:
			return locateAnswer(mainRel), nil
		case 2:
			return editCall("e1", "new Random()", "new java.security.SecureRandom()"), nil
		}
		return nil, errors.New("Sherrinford returned 502")
	})
	_, err := d.run(context.Background(), []appknox.AutofixUnit{unitToFix})
	require.ErrorContains(t, err, "502")
	got, _ := readUnderRoot(sess.root, mainRel)
	require.Equal(t, mainBody, got)
}

func TestSummarizeUnit(t *testing.T) {
	status, detail := summarizeUnit([]targetResult{{Path: "a", Patched: true}}, []string{"not found in repo: X", " "})
	require.Equal(t, "FIXED", status)
	require.Equal(t, "a; not found in repo: X", detail)

	status, detail = summarizeUnit([]targetResult{{Path: "a", Patched: true}, {Path: "b", Reason: reasonDeclined}}, nil)
	require.Equal(t, "PARTIAL", status)
	require.Equal(t, "a ok; b "+reasonDeclined, detail)

	status, detail = summarizeUnit(nil, nil)
	require.Equal(t, "SKIPPED", status)
	require.Equal(t, "locate: no targets", detail)
}
