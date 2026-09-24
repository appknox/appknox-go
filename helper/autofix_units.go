package helper

import (
	"context"
	"errors"
	"fmt"

	"github.com/appknox/appknox-go/agent"
	"github.com/appknox/appknox-go/fixservice"
)

// One KnoxIQ finding at a time: locate every file its remediation touches,
// validate the agent's answer, then fix each accepted file in its own call, in
// manifest → res → source order on the shared working tree (spec 3.1-3.3).

// unitResult is what one finding produced: the files it located, the patches
// already applied to the working tree, and its outcome line.
type unitResult struct {
	located []string
	patches []filePatch
	outcome findingOutcome
}

// targetContext is what one fix call is told about the rest of the remediation.
type targetContext struct {
	Why        string
	OtherFiles []agent.Target
}

// runUnit locates and fixes one KnoxIQ finding.
//
// The error is non-nil only when the whole run must stop: gateway budget
// exhaustion (the caller truncates), a working-tree write failure, or any
// call error on the manual --finding path, which has always failed fast.
// Every other miss is recorded in the outcome, and the run moves on.
//
// The outcome's Title is always stamped with u.Title on the way out (spec
// 3.4 / F2), whichever branch below produced it, so sibling findings of the
// same analysis -- which otherwise share an identical vulnerability id and
// analysis name -- can be told apart on their outcome line.
func (s fixSession) runUnit(ctx context.Context, in FindingInputs, u FindingUnit) (res unitResult, err error) {
	defer func() { res.outcome.Title = u.Title }()

	reply, locateErr := s.locateUnit(ctx, in, u)
	if locateErr != nil {
		return s.locateFailed(in, locateErr)
	}
	accepted, rejected := validateTargets(s.root, reply.Targets)
	res = unitResult{located: targetPaths(accepted)}
	results := rejectionResults(rejected)
	notes := notFoundNotes(reply.NotFound)
	if s.opts.LocateOnly {
		res.outcome = locatedOutcome(in, accepted, results, notes)
		return res, nil
	}
	if u.Remediation == "" {
		// A fix built on no instruction is worse than no fix.
		res.outcome = summarizeFinding(in.VulnerabilityID, in.Finding, results,
			append(notes, "no remediation to apply"))
		return res, nil
	}
	for _, t := range accepted {
		tr, patch, fixErr := s.fixOne(ctx, in, u, t, accepted)
		results = append(results, tr)
		if patch != nil {
			res.patches = append(res.patches, *patch)
		}
		if fixErr != nil {
			res.outcome = summarizeFinding(in.VulnerabilityID, in.Finding, results, notes)
			return res, fixErr
		}
	}
	res.outcome = summarizeFinding(in.VulnerabilityID, in.Finding, results, notes)
	return res, nil
}

// locateUnit runs the locate turn for one finding, on LocateModel first.
func (s fixSession) locateUnit(ctx context.Context, in FindingInputs, u FindingUnit) (agent.TargetReply, error) {
	reply, err := s.d.locateTargets(ctx,
		agent.Config{Host: s.host, Token: s.token, Model: firstNonEmpty(s.opts.LocateModel, s.opts.Model)},
		agent.TargetRequest{RepoRoot: s.root, VulnerabilityID: in.VulnerabilityID, Finding: in.Finding,
			Title: u.Title, Description: u.Description, Remediation: u.Remediation, ClassHint: u.ClassHint})
	s.tally.record(err)
	return reply, err
}

// locateFailed turns a failed locate into the finding's outcome, and decides
// whether the run stops.
func (s fixSession) locateFailed(in FindingInputs, err error) (unitResult, error) {
	if errors.Is(err, agent.ErrUnparseableReply) {
		return unitResult{outcome: summarizeFinding(in.VulnerabilityID, in.Finding, nil,
			[]string{"locate: unparseable reply"})}, nil
	}
	res := unitResult{outcome: summarizeFinding(in.VulnerabilityID, in.Finding, nil,
		[]string{"locate failed: " + err.Error()})}
	if isGatewayBudgetExhausted(err) || s.opts.FileID <= 0 {
		return res, err
	}
	fmt.Printf("autofix: skipping %q: %v\n", in.Finding, err)
	return res, nil
}

// fixOne fixes one accepted target and applies its patch to the working tree,
// so the next call reads this one's change. Only this finding's remediation
// goes in, never a sibling finding's.
func (s fixSession) fixOne(
	ctx context.Context, in FindingInputs, u FindingUnit, t agent.Target, all []agent.Target,
) (targetResult, *filePatch, error) {
	unitIn := FindingInputs{Finding: in.Finding, Remediation: u.Remediation,
		DeveloperPrompt: u.DeveloperPrompt, Criteria: u.Criteria}
	res, reason, err := s.produceFixFor(ctx, t.Path, unitIn,
		targetContext{Why: t.Why, OtherFiles: othersThan(all, t.Path)})
	s.tally.record(err)
	if err != nil {
		tr := targetResult{Path: t.Path, Reason: "error: " + err.Error()}
		if isGatewayBudgetExhausted(err) || s.opts.FileID <= 0 {
			return tr, nil, err
		}
		fmt.Printf("autofix: skipping %s for %q: %v\n", t.Path, in.Finding, err)
		return tr, nil, nil
	}
	if !res.Changed || res.PatchedContent == "" {
		return targetResult{Path: t.Path, Reason: reason}, nil, nil
	}
	patch, err := s.applyPatch(t.Path, in.Finding, res)
	if err != nil {
		return targetResult{Path: t.Path, Reason: "error: " + err.Error()}, nil, err
	}
	return targetResult{Path: t.Path, Patched: true}, &patch, nil
}

// applyPatch writes the patch to the working tree and records it.
func (s fixSession) applyPatch(path, finding string, res fixservice.Result) (filePatch, error) {
	// Read the pre-patch content BEFORE applying, for the cosmetic advice
	// below; after apply it would compare a file to itself.
	before, readErr := readUnderRoot(s.root, path)
	if err := s.work.apply(path, res.PatchedContent); err != nil {
		return filePatch{}, err
	}
	advice := ""
	if readErr == nil {
		advice = formattingAdvice(path, before, res.PatchedContent)
	}
	return filePatch{Path: path, Content: res.PatchedContent, Diff: res.UnifiedDiff,
		Confidence: res.Confidence, Finding: finding, Formatting: advice}, nil
}

// mergeUnit folds one finding's result into the run's outcome.
func mergeUnit(out Outcome, located map[string]bool, res unitResult) Outcome {
	for _, p := range res.located {
		if !located[p] {
			located[p] = true
			out.Located = append(out.Located, p)
		}
	}
	out.Patches = append(out.Patches, res.patches...)
	if res.outcome.Status != "" {
		out.Findings = append(out.Findings, res.outcome)
	}
	return out
}

func targetPaths(ts []agent.Target) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Path)
	}
	return out
}

// othersThan is every target except path, for the fixer's "other files" block.
func othersThan(all []agent.Target, path string) []agent.Target {
	out := make([]agent.Target, 0, len(all))
	for _, t := range all {
		if t.Path != path {
			out = append(out, t)
		}
	}
	return out
}
