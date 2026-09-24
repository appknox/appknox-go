package helper

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

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
	Create     bool // the target is a new file
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
	var extraNotes []string
	created, existing, badNew := validateNewFiles(s.root, reply.NewFiles)
	// A file listed under both new_files and needs_new_file is placed: it is
	// created, not a reason to skip the finding.
	reply.NeedsNewFile = withoutNamed(reply.NeedsNewFile, created)
	if len(reply.NeedsNewFile) > 0 {
		// The locate model's claim is never trusted as-is: code validates it
		// against the checkout before a whole finding is skipped on it (a
		// live miss on mfva had Haiku list app/proguard-rules.pro and
		// app/build.gradle under needs_new_file for an "Application Logs"
		// finding, even though both already existed).
		newOnes, notNew := genuinelyNew(s.root, reply.NeedsNewFile)
		if len(newOnes) > 0 {
			// At least one claim holds: fixing the rest of the targets would
			// still leave the finding referring to a class or resource that
			// is not there, breaking the PR build. Skip the whole finding:
			// no validation, no fix calls, no patches. Applies in
			// --locate-only too, so the line is SKIPPED there, never
			// TARGETS.
			res = unitResult{outcome: findingOutcome{
				VulnerabilityID: in.VulnerabilityID,
				Finding:         in.Finding,
				Status:          statusSkipped,
				Detail:          reasonNeedsNewFile + ": " + strings.Join(newOnes, "; "),
			}}
			return res, nil
		}
		// Every claim was false: carry on with normal validation, locate-only
		// output and fixing, but keep the false claim visible on the line.
		extraNotes = notNewNotes(notNew)
	}
	if len(badNew) > 0 {
		// The rest of the remediation refers to the file it creates, so
		// none of it may land without it.
		res = unitResult{outcome: findingOutcome{VulnerabilityID: in.VulnerabilityID, Finding: in.Finding,
			Status: statusSkipped, Detail: reasonNewFileRejected + ": " + rejectionList(badNew)}}
		return res, nil
	}
	accepted, rejected := validateTargets(s.root, append(withoutPaths(reply.Targets, created), existing...))
	if bad := unanchoredNewFiles(created, accepted); len(bad) > 0 {
		res = unitResult{outcome: findingOutcome{VulnerabilityID: in.VulnerabilityID, Finding: in.Finding,
			Status: statusSkipped, Detail: reasonNewFileRejected + ": " + rejectionList(bad)}}
		return res, nil
	}
	if len(created) > 0 && s.opts.FixMode != "agent" && !s.opts.LocateOnly {
		// /v1/fix rewrites an uploaded file; it cannot create one. Refuse the
		// whole finding here rather than upload its other files first.
		res = unitResult{outcome: findingOutcome{VulnerabilityID: in.VulnerabilityID, Finding: in.Finding,
			Status: statusSkipped, Detail: reasonNewFileRejected + ": creating files needs --fix-mode agent"}}
		return res, nil
	}
	accepted = orderTargets(append(created, accepted...))
	res = unitResult{located: targetPaths(accepted)}
	results := rejectionResults(rejected)
	notes := append(notFoundNotes(reply.NotFound), extraNotes...)
	if u.ThirdParty && len(accepted) == 0 {
		// The library is the only place the fix could go, and it is not the
		// customer's to patch. Applies in --locate-only too.
		res.outcome = summarizeFinding(in.VulnerabilityID, in.Finding, results, notes)
		res.outcome.Status = statusSkipped
		res.outcome.Detail = joinNonEmpty([]string{reasonThirdPartyNoSource, res.outcome.Detail}, "; ")
		return res, nil
	}
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
	patches, fixed, fixErr := s.fixTargets(ctx, in, u, accepted)
	res.patches = patches
	res.outcome = summarizeFinding(in.VulnerabilityID, in.Finding, append(results, fixed...), notes)
	return res, fixErr
}

// reasonRolledBack replaces a patched target's result when its unit was
// rolled back by fixTargets.
const reasonRolledBack = "rolled back: this remediation lands whole or not at all"

// fixTargets fixes each accepted target in order on the shared working tree.
//
// A unit that edits a module build script is all-or-nothing. The build script
// runs last (targetRank), and its edit usually only makes sense together with
// the source edits before it: dropping jedis from app/build.gradle compiles
// only once ExportedActivity.java no longer uses it. checkRemovedDependency
// catches that case when the dependency's group is its package; this is the
// backstop for when it is not. If the build script was patched but another
// target was refused by the patch gate or failed, every file this unit
// patched is put back as it was before the unit ran, and the unit ships
// nothing. A target the fixer DECLINED does not trigger it: declining means
// the file needed no change (e.g. a manifest with no debuggable attribute).
func (s fixSession) fixTargets(
	ctx context.Context, in FindingInputs, u FindingUnit, accepted []agent.Target,
) ([]filePatch, []targetResult, error) {
	var patches []filePatch
	var results []targetResult
	var fixErr error
	before := map[string]string{}
	for _, t := range accepted {
		if content, err := readUnderRoot(s.root, t.Path); err == nil {
			before[t.Path] = content
		}
		tr, patch, err := s.fixOne(ctx, in, u, t, accepted)
		tr.New = t.New
		results = append(results, tr)
		if patch != nil {
			patches = append(patches, *patch)
		}
		if err != nil {
			// The run stops (budget exhausted, or the manual path), but a
			// truncated run still delivers what it has: judge this unit
			// first, so a half-applied build-script change never ships.
			fixErr = err
			break
		}
	}
	if !needsRollback(results) {
		return patches, results, fixErr
	}
	if err := s.rollBack(results, before); err != nil {
		return patches, results, err
	}
	return nil, rolledBack(results), fixErr
}

// rollBack writes each patched target back to its content before the unit.
func (s fixSession) rollBack(results []targetResult, before map[string]string) error {
	for _, r := range results {
		if !r.Patched {
			continue
		}
		if r.New {
			if err := s.work.remove(r.Path); err != nil {
				return fmt.Errorf("rolling back new file %s: %w", r.Path, err)
			}
			continue
		}
		content, ok := before[r.Path]
		if !ok {
			return fmt.Errorf("cannot roll back %s: its content before the fix was not read", r.Path)
		}
		if err := s.work.apply(r.Path, content); err != nil {
			return fmt.Errorf("rolling back %s: %w", r.Path, err)
		}
	}
	return nil
}

// needsRollback reports whether a unit must be undone as a whole:
//   - it patched a module build script while another target was refused by
//     the gate or failed; or
//   - it creates a file, and that file was not created, or any target was
//     refused or failed, or no existing file was changed to use it -- the new
//     file and the edits that refer to it (a manifest's
//     @xml/network_security_config, a call to SecureCryptoManager) are one
//     change, and a new file nothing uses fixes nothing.
//
// A declined EXISTING target alone triggers neither: it needed no change.
func needsRollback(results []targetResult) bool {
	script, hasNew, failed, usedBy := false, false, false, false
	for _, r := range results {
		switch {
		case r.New:
			hasNew = true
			failed = failed || !r.Patched
		case r.Patched:
			usedBy = true
		}
		if r.Patched && (isModuleBuildScript(r.Path) || isModuleRulesFile(r.Path)) {
			script = true
		}
		if !r.Patched && (strings.HasPrefix(r.Reason, "rejected by patch gate") || strings.HasPrefix(r.Reason, "error:")) {
			failed = true
		}
	}
	return (script && failed) || (hasNew && (failed || !usedBy))
}

// withoutPaths drops targets naming a file listed as new: the model sometimes
// lists a new file under targets too, where it would be refused as missing.
func withoutPaths(ts, drop []agent.Target) []agent.Target {
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d.Path] = true
	}
	out := make([]agent.Target, 0, len(ts))
	for _, t := range ts {
		if !skip[filepath.ToSlash(filepath.Clean(strings.TrimSpace(t.Path)))] {
			out = append(out, t)
		}
	}
	return out
}

// withoutNamed drops needs_new_file entries that name a file already placed
// in created, by path or by base name ("network_security_config.xml: ...").
func withoutNamed(entries []string, created []agent.Target) []string {
	names := map[string]bool{}
	for _, c := range created {
		names[c.Path] = true
		names[filepath.Base(c.Path)] = true
		names[strings.TrimSuffix(filepath.Base(c.Path), filepath.Ext(c.Path))] = true
	}
	var out []string
	for _, e := range entries {
		n := needsNewFileName(e)
		if names[n] || names[filepath.Base(n)] {
			continue
		}
		out = append(out, e)
	}
	return out
}

// unanchoredNewFiles returns the new files that are not in the same module
// source set (<module>/src/<set>/) as any existing target. A resource the
// app manifest references must be in the app's own res/, and a class the
// app calls in its own sources; anywhere else, the gate's on-disk check
// passes while the build does not.
func unanchoredNewFiles(created, existing []agent.Target) []rejection {
	sets := map[string]bool{}
	for _, t := range existing {
		if s := sourceSetOf(t.Path); s != "" {
			sets[s] = true
		}
	}
	var bad []rejection
	for _, c := range created {
		if !sets[sourceSetOf(c.Path)] {
			bad = append(bad, rejection{Path: c.Path, Reason: "not in the source set of any file that uses it"})
		}
	}
	return bad
}

// sourceSetOf returns "<module>/src/<set>" for a path inside a source set.
func sourceSetOf(rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i := len(parts) - 2; i >= 0; i-- {
		if parts[i] == "src" && i+1 < len(parts)-1 {
			return strings.Join(parts[:i+2], "/")
		}
	}
	return ""
}

// rejectionList renders refused paths for an outcome line.
func rejectionList(rs []rejection) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		parts = append(parts, r.Path+" ("+r.Reason+")")
	}
	return strings.Join(parts, "; ")
}

// rolledBack marks every patched result as rolled back.
func rolledBack(results []targetResult) []targetResult {
	out := make([]targetResult, len(results))
	for i, r := range results {
		if r.Patched {
			r = targetResult{Path: r.Path, Reason: reasonRolledBack, New: r.New}
		}
		out[i] = r
	}
	return out
}

// locateUnit runs the locate turn for one finding, on LocateModel first.
func (s fixSession) locateUnit(ctx context.Context, in FindingInputs, u FindingUnit) (agent.TargetReply, error) {
	reply, err := s.d.locateTargets(ctx,
		agent.Config{Host: s.host, Token: s.token, Model: firstNonEmpty(s.opts.LocateModel, s.opts.Model)},
		agent.TargetRequest{RepoRoot: s.root, VulnerabilityID: in.VulnerabilityID, Finding: in.Finding,
			Title: u.Title, Description: u.Description, Remediation: u.Remediation, ClassHint: u.ClassHint,
			ThirdParty: u.ThirdParty})
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
		targetContext{Why: t.Why, OtherFiles: othersThan(all, t.Path), Create: t.New})
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
