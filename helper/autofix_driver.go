package helper

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/appknox/appknox-go/appknox"
)

// The autofix job, driven from this checkout. Per KnoxIQ finding:
//
//  1. a locate turn: Appknox's model reads the checkout through this CLI and
//     answers with the files the remediation changes;
//  2. validate_targets checks that answer against the checkout;
//  3. per accepted target: begin_target snapshots the file, a fix turn edits
//     it, and verify_target holds the patch to the static gate. A refused
//     patch is retried once with the violated fact;
//  4. finish_unit rolls the finding back when it must land whole and did not.
//
// Only the model turns leave this machine, one HTTP call per model step. The
// prompts, the remediation text and the conversation stay on Appknox.

const (
	statusFixed   = "FIXED"
	statusPartial = "PARTIAL"

	reasonDeclined    = "declined: no edit made"
	reasonModelFailed = "error: model call failed"

	// maxFixRetries: the gate tells the fixer the one fact it could not see;
	// a second miss on the same fact is not a third-attempt problem.
	maxFixRetries = 1
)

// modelTools are the only calls a turn may ask this CLI to run. The
// orchestration ops are this CLI's own and are never taken from the wire.
var modelTools = map[string]bool{
	toolReadFile: true, toolGrep: true, toolGlob: true, toolEdit: true, toolCreateFile: true,
}

// turnFunc sends one call of a model turn to Appknox.
type turnFunc func(ctx context.Context, req *appknox.AutofixTurnRequest) (*appknox.AutofixTurnResponse, error)

// autofixDriver walks a job's findings on one checkout.
type autofixDriver struct {
	sess    *autofixSession
	turn    turnFunc
	profile string // build facts every fix turn is told
	calls   int    // turn calls made; numbers the step lines
}

func newAutofixDriver(sess *autofixSession, turn turnFunc) *autofixDriver {
	return &autofixDriver{sess: sess, turn: turn, profile: describeBuild(sess.root).String()}
}

// run works through every finding in order. A finding that cannot be fixed
// is an outcome; an error talking to Appknox stops the run.
func (d *autofixDriver) run(ctx context.Context, units []appknox.AutofixUnit) ([]appknox.AutofixOutcome, error) {
	out := make([]appknox.AutofixOutcome, 0, len(units))
	for _, u := range units {
		o, err := d.runUnit(ctx, u)
		if err != nil {
			return out, err
		}
		out = append(out, o)
	}
	return out, nil
}

func (d *autofixDriver) runUnit(ctx context.Context, u appknox.AutofixUnit) (appknox.AutofixOutcome, error) {
	if u.SkipReason != "" {
		return unitOutcome(u, statusSkipped, u.SkipReason, nil), nil
	}
	done, err := d.runTurn(ctx, u.UnitID, &appknox.AutofixTurnStart{Kind: appknox.AutofixTurnLocate})
	if err != nil {
		return appknox.AutofixOutcome{}, err
	}
	if done.Answer == nil {
		return unitOutcome(u, statusSkipped, firstNonEmpty(done.Detail, "locate: no answer"), nil), nil
	}

	args := map[string]interface{}{}
	for k, v := range done.Answer {
		args[k] = v
	}
	args["unit_id"], args["third_party"] = u.UnitID, u.ThirdParty
	_, data, err := d.sess.validateTargets(args)
	if err != nil {
		return unitOutcome(u, statusSkipped, "validate failed: "+err.Error(), nil), nil
	}
	results := resultsOf(data["results"])
	if skip, _ := data["skip"].(bool); skip {
		status, _ := data["status"].(string)
		detail, _ := data["detail"].(string)
		return unitOutcome(u, firstNonEmpty(status, statusSkipped), detail, results), nil
	}
	var targets []appknox.AutofixFixTarget
	var notes []string
	_ = fromData(data["accepted"], &targets)
	_ = fromData(data["notes"], &notes)

	for i, t := range targets {
		r, err := d.fixTarget(ctx, u.UnitID, t, otherTargets(targets, i))
		if err != nil {
			return appknox.AutofixOutcome{}, err
		}
		results = append(results, r)
	}
	if _, fin, err := d.sess.finishUnit(map[string]interface{}{"results": results}); err == nil {
		results = resultsOf(fin["results"])
	}
	status, detail := summarizeUnit(results, notes)
	return unitOutcome(u, status, detail, results), nil
}

// fixTarget runs the fix turn for one file and holds its patch to the gate,
// retrying once when the gate refuses it.
func (d *autofixDriver) fixTarget(ctx context.Context, unitID string, t appknox.AutofixFixTarget,
	others []appknox.AutofixFixTarget) (targetResult, error) {
	violation, refused := "", ""
	for attempt := 0; ; attempt++ {
		if _, _, err := d.sess.beginTarget(map[string]interface{}{"path": t.Path, "new": t.New}); err != nil {
			// Nothing was snapshotted, so no edit of this file could be held.
			return unpatched(t, "error: "+err.Error()), nil
		}
		target := t
		done, err := d.runTurn(ctx, unitID, &appknox.AutofixTurnStart{Kind: appknox.AutofixTurnFix,
			Target: &target, Others: others, Profile: d.profile, Violation: violation})
		if err != nil {
			_, _, _ = d.sess.verifyTarget(map[string]interface{}{"path": t.Path, "discard": true})
			return targetResult{}, err
		}
		// A failed turn may have left edits on disk: put the file back.
		_, data, err := d.sess.verifyTarget(map[string]interface{}{"path": t.Path, "discard": done.Failed})
		if err != nil {
			return unpatched(t, "error: "+err.Error()), nil
		}
		v, _ := data["violation"].(map[string]interface{})
		changed, _ := data["changed"].(bool)
		accepted, _ := data["accepted"].(bool)
		switch {
		case done.Failed:
			return unpatched(t, reasonModelFailed), nil
		case !changed && refused != "":
			// The file needed a change the gate would not allow, which is not
			// the same as needing none.
			return unpatched(t, "rejected by patch gate ("+refused+"), then declined"), nil
		case !changed:
			return unpatched(t, reasonDeclined), nil
		case accepted:
			return targetResult{Path: t.Path, Patched: true, New: t.New}, nil
		case v != nil && attempt < maxFixRetries:
			// The file is back to its original; the next turn is told why.
			violation = firstNonEmpty(strOf(v["detail"]), strOf(v["rule"]))
			refused = strOf(v["rule"])
		default:
			return unpatched(t, "rejected by patch gate ("+firstNonEmpty(strOf(v["rule"]), "unknown")+")"), nil
		}
	}
}

// runTurn opens a turn and answers its tool calls until it ends.
func (d *autofixDriver) runTurn(ctx context.Context, unitID string, start *appknox.AutofixTurnStart) (*appknox.AutofixTurnResponse, error) {
	req := &appknox.AutofixTurnRequest{UnitID: unitID, Start: start}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		d.calls++
		resp, err := d.turn(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Type != appknox.AutofixTurnToolCalls {
			return resp, nil
		}
		if len(resp.Calls) == 0 {
			return nil, errors.New("autofix: a turn asked for no tool calls")
		}
		fmt.Printf("    step %d: %s\n", d.calls, callSummary(resp.Calls))
		req = &appknox.AutofixTurnRequest{UnitID: unitID, ToolResults: d.runModelCalls(resp.Calls)}
	}
}

// runModelCalls answers a turn's calls in order, refusing anything that is
// not a model tool.
func (d *autofixDriver) runModelCalls(calls []appknox.AutofixToolCall) []appknox.AutofixToolResult {
	out := make([]appknox.AutofixToolResult, 0, len(calls))
	for _, c := range calls {
		if !modelTools[c.Name] {
			out = append(out, appknox.AutofixToolResult{ID: c.ID, Content: fmt.Sprintf("unknown tool %q", c.Name), IsError: true})
			continue
		}
		out = append(out, d.sess.runAll([]appknox.AutofixToolCall{c})...)
	}
	return out
}

// summarizeUnit is a finding's status and detail from its per-file results.
// A not-found note never downgrades FIXED: those names are framework or
// library code. A refused, declined or failed target does, because part of
// the remediation was not applied.
func summarizeUnit(results []targetResult, notes []string) (string, string) {
	var ok, failed []string
	for _, r := range results {
		if r.Patched {
			ok = append(ok, r.Path)
		} else {
			failed = append(failed, strings.TrimSpace(r.Path+" "+r.Reason))
		}
	}
	var kept []string
	for _, n := range notes {
		if strings.TrimSpace(n) != "" {
			kept = append(kept, n)
		}
	}
	switch {
	case len(ok) > 0 && len(failed) == 0:
		return statusFixed, strings.Join(append([]string{strings.Join(ok, ", ")}, kept...), "; ")
	case len(ok) > 0:
		parts := append([]string{strings.Join(ok, ", ") + " ok"}, failed...)
		return statusPartial, strings.Join(append(parts, kept...), "; ")
	}
	return statusSkipped, firstNonEmpty(strings.Join(append(failed, kept...), "; "), "locate: no targets")
}

func unitOutcome(u appknox.AutofixUnit, status, detail string, results []targetResult) appknox.AutofixOutcome {
	files := make([]appknox.AutofixTargetOutcome, 0, len(results))
	for _, r := range results {
		files = append(files, appknox.AutofixTargetOutcome{Path: r.Path, Patched: r.Patched, Reason: r.Reason, New: r.New})
	}
	return appknox.AutofixOutcome{UnitID: u.UnitID, VulnerabilityID: u.VulnerabilityID, Finding: u.Finding,
		Title: u.Title, Status: status, Detail: detail, Files: files}
}

func unpatched(t appknox.AutofixFixTarget, reason string) targetResult {
	return targetResult{Path: t.Path, Reason: reason, New: t.New}
}

func otherTargets(ts []appknox.AutofixFixTarget, skip int) []appknox.AutofixFixTarget {
	out := make([]appknox.AutofixFixTarget, 0, len(ts))
	for i, t := range ts {
		if i != skip && t.Path != ts[skip].Path {
			out = append(out, t)
		}
	}
	return out
}

func resultsOf(v interface{}) []targetResult {
	var out []targetResult
	_ = fromData(v, &out)
	return out
}

func strOf(v interface{}) string {
	s, _ := v.(string)
	return s
}
