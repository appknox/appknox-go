package helper

import (
	"context"
	"errors"
	"fmt"
)

// A run covers a WHOLE FILE by default, not one finding.
//
// Asking a developer which analysis id to fix is asking them to redo the triage
// the scanner already did. Given just --file-id, every locatable analysis is
// attempted and the results land in ONE pull request -- one branch per scan
// rather than one per finding, which is the difference between a review and an
// inbox.

// analysisTarget is one analysis to attempt, with its resolved inputs.
type analysisTarget struct {
	AnalysisID int
	Inputs     FindingInputs
}

// analysisReport records what happened for one analysis, delivered or not.
type analysisReport struct {
	AnalysisID   int
	Finding      string
	Located      []string
	Patches      int
	Verification VerificationReport
	Skipped      string // why nothing from this analysis was delivered
}

// resolveTargets decides what this run will attempt.
//
//   - --file-id with --analysis-id: just that one.
//   - --file-id alone: every analysis naming a first-party class. That filter is
//     local and free; without it we would ask KnoxIQ about scores of analyses
//     that could never be located anyway.
//   - --finding: the manual escape hatch, no Appknox lookup at all.
func resolveTargets(ctx context.Context, opts AutofixOptions, d autofixDeps) ([]analysisTarget, error) {
	if opts.FileID > 0 && opts.AnalysisID > 0 {
		inputs, err := d.fetch(ctx, opts.FileID, opts.AnalysisID)
		if err != nil {
			return nil, err
		}
		return []analysisTarget{{AnalysisID: opts.AnalysisID, Inputs: inputs}}, nil
	}
	if opts.FileID > 0 {
		return everyLocatableAnalysis(ctx, opts, d)
	}
	if opts.Finding == "" {
		return nil, errors.New(
			"provide --file-id (fixes every finding), --file-id + --analysis-id (one), or --finding")
	}
	return []analysisTarget{{
		Inputs: FindingInputs{Finding: opts.Finding, ClassHints: []string{opts.ClassHint}},
	}}, nil
}

// everyLocatableAnalysis resolves inputs for each candidate analysis on a file.
//
// One analysis failing does not abandon the rest: a single unreachable or
// malformed finding should not cost the developer every other fix in the scan.
// Those are reported and the run continues.
func everyLocatableAnalysis(
	ctx context.Context, opts AutofixOptions, d autofixDeps,
) ([]analysisTarget, error) {
	ids, err := d.analysisIDs(ctx, opts.FileID)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no analysis on file %d names a first-party class to fix", opts.FileID)
	}
	fmt.Printf("Considering %d analyses on file %d\n", len(ids), opts.FileID)

	targets := make([]analysisTarget, 0, len(ids))
	for _, id := range ids {
		inputs, err := d.fetch(ctx, opts.FileID, id)
		if err != nil {
			fmt.Printf("  analysis %d: skipped (%v)\n", id, err)
			continue
		}
		if inputs.Remediation == "" {
			continue // KnoxIQ judged nothing here worth fixing
		}
		targets = append(targets, analysisTarget{AnalysisID: id, Inputs: inputs})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("KnoxIQ has nothing fixable on file %d", opts.FileID)
	}
	fmt.Printf("%d analysis(es) have a fix to attempt\n", len(targets))
	return targets, nil
}

// locatableAnalysisIDs returns the analyses on a file that reference a
// first-party class -- the ones a fix could actually be located for.
func locatableAnalysisIDs(ctx context.Context, fileID int) ([]int, error) {
	all, err := allAnalyses(ctx, getClient(), fileID)
	if err != nil {
		return nil, err
	}
	var ids []int
	for _, a := range all {
		if len(classHintsFromFindings(findingsText(a))) > 0 {
			ids = append(ids, a.ID)
		}
	}
	return ids, nil
}
