package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/toolrunner"
)

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
}

// FixResult is the outcome of a client-side agent fix. It is side-effect-free:
// the on-disk file is restored to its original, and PatchedContent holds the
// fixed version for the caller to apply/deliver.
type FixResult struct {
	Changed        bool
	PatchedContent string
	Diff           string
	// Reason is the fixer's own closing account of what it did, and above all
	// why it declined when it made no edit.
	//
	// The contract tells the model to make NO edit and say why rather than
	// guess, so declining is an expected outcome -- but the explanation used to
	// be discarded here, which left "the fixer produced no edit" as the whole
	// story in the logs and made a decline impossible to diagnose after the fact.
	Reason string
}

// fixRunner runs the edit agent, applying edits on disk and recording them,
// and captures the model's closing message in reason.
type fixRunner func(ctx context.Context, cfg Config, req FixRequest,
	edits *[]editRecord, reason *string) error

// FixFile fixes the located file locally via the agent's edit tool — NO file is
// uploaded (only the model turns cross the gateway). Returns the patched content
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
	var reason string
	runErr := run(ctx, cfg, req, &edits, &reason)
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
		Reason:         strings.TrimSpace(reason),
	}, nil
}

// sdkFix drives the Tool Runner with read-only tools + the edit tool, routed
// through the gateway.
func sdkFix(ctx context.Context, cfg Config, req FixRequest,
	edits *[]editRecord, reason *string) error {
	if cfg.FixURL == "" || cfg.Token == "" {
		return errors.New("agent: FixURL and Token are required to reach the gateway")
	}
	tools, err := buildFixTools(req.RepoRoot, req.Path, edits)
	if err != nil {
		return err
	}
	client := anthropic.NewClient(
		option.WithBaseURL(strings.TrimRight(cfg.FixURL, "/")+"/anthropic"),
		option.WithAPIKey(cfg.Token),
	)
	runner := client.Beta.Messages.NewToolRunner(tools, runnerParams(cfg, fixSystemPrompt, fixUserPrompt(req)))
	final, err := runner.RunToCompletion(ctx)
	// Keep the closing message even when the run errored: a partial explanation
	// is often the only account of what the fixer was attempting.
	*reason = extractText(final)
	return err
}

// buildFixTools = read-only Read/Grep/Glob + the edit tool (restricted to allowedPath).
func buildFixTools(root, allowedPath string, edits *[]editRecord) ([]anthropic.BetaTool, error) {
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
