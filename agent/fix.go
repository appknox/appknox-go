package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/toolrunner"
)

// fixSystemPrompt and fixUserPrompt live in instructions.go, which tailors them
// to the project type (Gradle/Maven/Java/…) detected from the build files.

// FixRequest describes the located file + finding to fix in place.
type FixRequest struct {
	RepoRoot    string
	Path        string
	Finding     string
	Remediation string
	// DeveloperPrompt is KnoxIQ's guidance written for a human developer --
	// more specific than the generic remediation prose when present.
	DeveloperPrompt string
	// Criteria are the checks the patch will be measured against, passed in so
	// the fixer aims at them rather than discovering a miss afterwards.
	Criteria []string
	// ProjectProfile states what kind of project this is -- build system, AGP
	// version, compileSdk, whether BuildConfig is generated -- read from the
	// build files on disk.
	//
	// The fixer sees ONE file and cannot infer any of this from it. Handing it
	// over up front is cheaper than letting the gate reject a patch that
	// guessed wrong and then paying for a retry.
	ProjectProfile string
	// PriorViolation is the fact a previous attempt at this same file got wrong
	// -- a build script it may not edit, XML it left unparseable, a resource or
	// type that is not in the checkout. Set only on a retry, and only ever once.
	//
	// It is a fact about the repository, not a critique. The fixer has no
	// compiler and can see only its one file, so "@xml/foo does not exist here"
	// is information the prompt by itself could never supply -- which is why
	// two repos given the same remediation and the same rule still diverged.
	PriorViolation string
}

// FixResult is the outcome of a client-side agent fix. It is side-effect-free:
// the on-disk file is restored to its original, and PatchedContent holds the
// fixed version for the caller to apply/deliver.
type FixResult struct {
	Changed        bool
	PatchedContent string
	Diff           string
}

// fixRunner runs the edit agent, applying edits on disk and recording them.
type fixRunner func(ctx context.Context, cfg Config, req FixRequest, edits *[]editRecord) error

// FixFile fixes the located file locally via the agent's edit tool — NO file is
// uploaded (only the model turns go to Mycroft). Returns the patched content
// and leaves the on-disk file unchanged; the caller applies or delivers it.
func FixFile(ctx context.Context, cfg Config, req FixRequest) (FixResult, error) {
	return fixWith(ctx, cfg, req, sdkFix)
}

func fixWith(ctx context.Context, cfg Config, req FixRequest, run fixRunner) (FixResult, error) {
	abs, err := resolveUnderRoot(req.RepoRoot, req.Path)
	if err != nil {
		return FixResult{}, err
	}
	original, err := os.ReadFile(abs)
	if err != nil {
		return FixResult{}, err
	}
	var edits []editRecord
	runErr := run(ctx, cfg, req, &edits)
	patched, readErr := os.ReadFile(abs)
	revertErr := os.WriteFile(abs, original, 0o644) // revert: FixFile leaves disk unchanged
	if runErr != nil {
		return FixResult{}, runErr
	}
	if readErr != nil {
		return FixResult{}, fmt.Errorf("agent: reading patched file %s: %w", req.Path, readErr)
	}
	if revertErr != nil { // restore failed → disk NOT left unchanged; fail loudly
		return FixResult{}, fmt.Errorf("agent: restoring %s after fix: %w", req.Path, revertErr)
	}
	return FixResult{
		Changed:        !bytes.Equal(original, patched),
		PatchedContent: string(patched),
		Diff:           buildDiff(edits),
	}, nil
}

// sdkFix drives the Tool Runner with read-only tools + the edit tool, routed
// through Mycroft.
func sdkFix(ctx context.Context, cfg Config, req FixRequest, edits *[]editRecord) error {
	if cfg.Host == "" || cfg.Token == "" {
		return errors.New("agent: Host and Token are required to reach Mycroft")
	}
	tools, err := buildFixTools(req.RepoRoot, req.Path, edits)
	if err != nil {
		return err
	}
	client := newAutofixSDK(cfg)
	runner := client.Beta.Messages.NewToolRunner(tools, fixParams(cfg, req))
	final, err := runner.RunToCompletion(ctx)
	if err != nil {
		return err
	}
	// A run that recorded an edit succeeded; nothing left to explain. It is the
	// empty-handed run that has to say WHY, because "no edit" reaches the caller
	// as a clean skip and reads exactly like the model judging the file safe.
	if len(*edits) == 0 {
		if reason := declineReason(final); reason != "" {
			fmt.Printf("  fixer made no edit to %s: %s\n", req.Path, reason)
		}
	}
	return nil
}

// fixParams builds the Tool Runner params for the FIX pass, on the fix turn's
// own output-token budget rather than the locate turn's.
func fixParams(cfg Config, req FixRequest) sdk.BetaToolRunnerParams {
	return runnerParamsWithBudget(cfg, fixSystemPrompt, fixUserPrompt(req), defaultFixMaxTokens)
}

// declineReason explains an empty-handed fix turn.
//
// A truncated or iteration-capped run leaves a final message with no text at
// all. Reporting that as silence would make it look like the model chose to
// abstain, when in fact it never got to finish -- two problems with opposite
// fixes, and for a while they were indistinguishable in the logs.
func declineReason(final *sdk.BetaMessage) string {
	if final == nil {
		return "the fixer returned no final message"
	}
	if text := strings.TrimSpace(extractText(final)); text != "" {
		return text
	}
	switch final.StopReason {
	case sdk.BetaStopReasonMaxTokens:
		return "the reply hit the output-token limit before the edit completed; " +
			"the fix was too large for the budget, not declined"
	case sdk.BetaStopReasonRefusal:
		return "the model refused the request"
	}
	return ""
}

// buildFixTools = read-only Read/Grep/Glob + the edit tool (restricted to allowedPath).
func buildFixTools(root, allowedPath string, edits *[]editRecord) ([]sdk.BetaTool, error) {
	tools, err := buildLocateTools(root)
	if err != nil {
		return nil, err
	}
	edit, err := toolrunner.NewBetaToolFromJSONSchema(
		"edit", "Replace old_string with new_string in the target file (old_string must be unique).",
		editHandler(root, allowedPath, edits))
	if err != nil {
		return nil, err
	}
	return append(tools, edit), nil
}

// buildDiff renders the recorded edits as a simple -old/+new diff.
func buildDiff(edits []editRecord) string {
	var b strings.Builder
	for _, e := range edits {
		fmt.Fprintf(&b, "--- %s\n", e.Path)
		for _, line := range strings.Split(strings.TrimRight(e.Old, "\n"), "\n") {
			b.WriteString("- " + line + "\n")
		}
		for _, line := range strings.Split(strings.TrimRight(e.New, "\n"), "\n") {
			b.WriteString("+ " + line + "\n")
		}
	}
	return b.String()
}
