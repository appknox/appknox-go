package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/appknox/appknox-go/agent"
	"github.com/appknox/appknox-go/appknox"
)

// mycroftJob is the autofix job Mycroft's worker is serving. Model turns go
// to POST .../turn/; the CLI only runs the tool calls on its checkout.
type mycroftJob struct {
	fileID int
	id     int
	done   *bool
}

const mycroftTurnLimit = 15

// fixResult is one fix turn's outcome: the target's content after the turn.
// The checkout itself is restored before the result is returned.
type fixResult struct {
	Changed        bool
	PatchedContent string
	UnifiedDiff    string
}

// maxViolationDetail is the longest gate report Mycroft accepts.
const maxViolationDetail = 1000

// capRunes cuts s to at most n characters, the unit Mycroft counts in.
func capRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// targetsFromUnits turns the worker's public findings into the run's targets.
// A unit with a skip reason is not located. Remediation text stays on the
// worker, so a unit the CLI will attempt carries only its id.
func targetsFromUnits(units *[]appknox.AutofixUnit) []analysisTarget {
	if units == nil {
		return nil
	}
	out := make([]analysisTarget, 0, len(*units))
	for _, u := range *units {
		vid := 0
		if u.VulnerabilityID != nil {
			vid = *u.VulnerabilityID
		}
		in := FindingInputs{
			Finding:         u.Finding,
			VulnerabilityID: vid,
			UnitID:          u.UnitID,
		}
		skip := ""
		if u.SkipReason != nil {
			skip = strings.TrimSpace(*u.SkipReason)
		}
		if skip != "" {
			in.SkipReason = skip
		} else {
			third := false
			if u.ThirdParty != nil {
				third = *u.ThirdParty
			}
			in.Units = []FindingUnit{{
				UnitID:     u.UnitID,
				Title:      u.Title,
				ThirdParty: third,
			}}
		}
		out = append(out, analysisTarget{Inputs: in})
	}
	return out
}

func (s fixSession) locateViaMycroft(ctx context.Context, u FindingUnit) (agent.TargetReply, error) {
	resp, err := s.driveTurn(ctx, u.UnitID, &appknox.AutofixTurnStart{Kind: "locate"}, "")
	if err != nil {
		return agent.TargetReply{}, err
	}
	if resp.Failed || len(resp.Answer) == 0 || string(resp.Answer) == "null" {
		detail := resp.Detail
		if strings.Contains(detail, "unparseable") {
			return agent.TargetReply{}, agent.ErrUnparseableReply
		}
		if detail == "" {
			detail = "locate failed"
		}
		return agent.TargetReply{}, errors.New(detail)
	}
	var reply agent.TargetReply
	if err := json.Unmarshal(resp.Answer, &reply); err != nil || reply.Targets == nil {
		return agent.TargetReply{}, agent.ErrUnparseableReply
	}
	return reply, nil
}

func (s fixSession) fixViaMycroft(ctx context.Context, path string, tc targetContext, prior *patchViolation) (fixResult, error) {
	abs, err := safeDest(s.root, path)
	if err != nil {
		return fixResult{}, err
	}
	var original []byte
	existed := false
	if !tc.Create {
		original, err = os.ReadFile(abs)
		if err != nil {
			return fixResult{}, err
		}
		existed = true
	}
	defer func() {
		if existed {
			_ = os.WriteFile(abs, original, 0o644)
			return
		}
		_ = os.Remove(abs)
	}()

	others := make([]appknox.AutofixTarget, 0, len(tc.OtherFiles))
	for _, o := range tc.OtherFiles {
		others = append(others, appknox.AutofixTarget{Path: o.Path, New: o.New})
	}
	var violation *appknox.AutofixViolation
	if prior != nil {
		violation = &appknox.AutofixViolation{Rule: prior.Rule, Detail: capRunes(prior.Detail, maxViolationDetail)}
	}
	resp, err := s.driveTurn(ctx, tc.UnitID, &appknox.AutofixTurnStart{
		Kind:      "fix",
		Profile:   s.build.wire(),
		Violation: violation,
		Target:    &appknox.AutofixTarget{Path: path, New: tc.Create},
		Others:    others,
	}, path)
	if err != nil {
		return fixResult{}, err
	}
	if resp.Failed {
		detail := resp.Detail
		if detail == "" {
			detail = "fix failed"
		}
		return fixResult{}, errors.New(detail)
	}
	patched, readErr := os.ReadFile(abs)
	if readErr != nil {
		return fixResult{}, nil
	}
	if existed && string(patched) == string(original) {
		return fixResult{}, nil
	}
	before := ""
	if existed {
		before = string(original)
	}
	return fixResult{
		Changed: true, PatchedContent: string(patched), UnifiedDiff: unifiedDiff(path, before, string(patched)),
	}, nil
}

// driveTurn opens or resumes one turn until Sherrinford stops asking for tools.
func (s fixSession) driveTurn(ctx context.Context, unitID string, start *appknox.AutofixTurnStart, allowed string) (*appknox.AutofixTurnResponse, error) {
	if s.job == nil {
		return nil, errors.New("autofix turn without a Mycroft job")
	}
	client := getClient()
	if client == nil {
		return nil, errors.New("autofix turn failed: missing Appknox client")
	}
	resp, _, err := client.KnoxIQ.AutofixTurn(ctx, s.job.fileID, s.job.id, &appknox.AutofixTurnRequest{
		UnitID: unitID, Start: start,
	})
	if err != nil {
		return nil, err
	}
	for hop := 0; resp != nil && resp.Type == "tool_calls"; hop++ {
		if hop >= mycroftTurnLimit {
			return nil, fmt.Errorf("autofix turn for %s exceeded %d tool rounds", unitID, mycroftTurnLimit)
		}
		results := make([]appknox.AutofixToolResult, 0, len(resp.Calls))
		for _, call := range resp.Calls {
			text, toolErr := agent.ExecTool(s.root, call.Name, call.Args, allowed)
			result := appknox.AutofixToolResult{ID: call.ID, Content: text}
			if toolErr != nil {
				result.IsError = true
				result.Content = toolErr.Error()
			}
			results = append(results, result)
		}
		resp, _, err = client.KnoxIQ.AutofixTurn(ctx, s.job.fileID, s.job.id, &appknox.AutofixTurnRequest{
			UnitID: unitID, ToolResults: results,
		})
		if err != nil {
			return nil, err
		}
	}
	if resp == nil || resp.Type != "done" {
		got := ""
		if resp != nil {
			got = resp.Type
		}
		return nil, fmt.Errorf("autofix turn for %s ended as %q", unitID, got)
	}
	return resp, nil
}

// finishJob sends outcomes to Mycroft so the worker can stop waiting.
// The title comes back for the pull request. The body Mycroft returns is not
// what GitHub stores: the caller renders that description itself.
// This method has a value receiver, so it cannot write them onto s.opts.
func (s fixSession) finishJob(ctx context.Context, out *Outcome) (title, body string, err error) {
	if s.job == nil {
		return "", "", nil
	}
	client := getClient()
	if client == nil {
		return "", "", errors.New("autofix complete failed: missing Appknox client")
	}
	req, _, err := client.KnoxIQ.AutofixComplete(ctx, s.job.fileID, s.job.id, outcomesForJob(out.Findings, out.Patches))
	if err != nil {
		return "", "", fmt.Errorf("autofix complete failed: %w", err)
	}
	if s.job.done != nil {
		*s.job.done = true
	}
	if req != nil && req.PR != nil {
		title, body = req.PR.Title, req.PR.Body
	}
	return title, body, nil
}

func outcomesForJob(findings []findingOutcome, patches []filePatch) []appknox.AutofixOutcome {
	out := make([]appknox.AutofixOutcome, 0, len(findings))
	for _, f := range findings {
		if f.UnitID == "" {
			continue
		}
		status := f.Status
		if status == statusTargets {
			status = statusSkipped
		}
		var vid *int
		if f.VulnerabilityID != 0 {
			id := f.VulnerabilityID
			vid = &id
		}
		item := appknox.AutofixOutcome{
			UnitID: f.UnitID, VulnerabilityID: vid, Finding: f.Finding, Title: f.Title,
			Status: status, Detail: f.Detail,
		}
		for _, p := range patches {
			if f.Finding != "" && (p.Finding == f.Finding || strings.Contains(p.Finding, f.Finding)) {
				item.Files = append(item.Files, appknox.AutofixTargetOutcome{Path: p.Path, Patched: true})
			}
		}
		out = append(out, item)
	}
	return out
}

// headSHA is the checkout's HEAD, sent so Mycroft can name the commit the
// job started from. Empty when the path is not a git checkout.
func headSHA(repoPath string) string {
	if strings.TrimSpace(repoPath) == "" {
		return ""
	}
	out, err := exec.Command("git", "-C", repoPath, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
