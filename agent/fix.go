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
	// NewFiles are files the fix added, for the caller to deliver.
	//
	// A remediation often prescribes a new unit of code rather than an edit to
	// an existing one -- "introduce a SecureCryptoManager class, then call it
	// from the fixed method". Without this the fixer can only rewrite the
	// located file, so it has to decline such a remediation outright and the
	// finding stays open.
	//
	// Like PatchedContent these are captured rather than left behind: the
	// created files are removed from disk before FixFile returns.
	NewFiles []NewFile
}

// NewFile is a file the fix created.
type NewFile struct {
	Path    string
	Content string
}

// fixRunner runs the edit agent, applying edits on disk and recording them,
// plus any files the fix created so the caller can deliver and then unwind them.
type fixRunner func(ctx context.Context, cfg Config, req FixRequest,
	edits *[]editRecord, created *[]createdFile) error

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
	var created []createdFile
	runErr := run(ctx, cfg, req, &edits, &created)
	patched, readErr := os.ReadFile(abs)
	revertErr := os.WriteFile(abs, original, 0o644) // revert: FixFile leaves disk unchanged
	// Unwind creations unconditionally, even on a failed run: a run that errored
	// part-way can still have created files, and one left behind would be read by
	// the next analysis in this run as if it were the developer's own code.
	removeErr := removeCreated(req.RepoRoot, created)
	if runErr != nil {
		return FixResult{}, runErr
	}
	if removeErr != nil { // disk NOT left unchanged; fail loudly, as with revert
		return FixResult{}, fmt.Errorf("agent: removing files created by the fix: %w", removeErr)
	}
	if readErr != nil {
		return FixResult{}, fmt.Errorf("agent: reading patched file %s: %w", req.Path, readErr)
	}
	if revertErr != nil { // restore failed → disk NOT left unchanged; fail loudly
		return FixResult{}, fmt.Errorf("agent: restoring %s after fix: %w", req.Path, revertErr)
	}
	return FixResult{
		// A fix that only added a file still changed the codebase. Reporting
		// Changed=false there would drop the new file at the caller, which
		// treats an unchanged result as "nothing to deliver".
		Changed:        !bytes.Equal(original, patched) || len(created) > 0,
		PatchedContent: string(patched),
		Diff:           buildDiff(edits),
		NewFiles:       newFiles(created),
	}, nil
}

// newFiles converts the captured creations for the caller.
func newFiles(created []createdFile) []NewFile {
	if len(created) == 0 {
		return nil
	}
	out := make([]NewFile, 0, len(created))
	for _, f := range created {
		out = append(out, NewFile{Path: f.Path, Content: f.Content})
	}
	return out
}

// sdkFix drives the Tool Runner with read-only tools + the edit tool, routed
// through the gateway.
func sdkFix(ctx context.Context, cfg Config, req FixRequest,
	edits *[]editRecord, created *[]createdFile) error {
	if cfg.FixURL == "" || cfg.Token == "" {
		return errors.New("agent: FixURL and Token are required to reach the gateway")
	}
	tools, err := buildFixTools(req.RepoRoot, req.Path, edits, created)
	if err != nil {
		return err
	}
	client := anthropic.NewClient(
		option.WithBaseURL(strings.TrimRight(cfg.FixURL, "/")+"/anthropic"),
		option.WithAPIKey(cfg.Token),
	)
	runner := client.Beta.Messages.NewToolRunner(tools, runnerParams(cfg, fixSystemPrompt, fixUserPrompt(req)))
	_, err = runner.RunToCompletion(ctx)
	return err
}

// buildFixTools = read-only Read/Grep/Glob + the edit tool (restricted to allowedPath).
func buildFixTools(root, allowedPath string, edits *[]editRecord,
	created *[]createdFile) ([]anthropic.BetaTool, error) {
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
	// create is deliberately separate from edit rather than a mode of it: edit
	// is restricted to the one located file, and that restriction is a safety
	// property worth keeping intact. Creating a NEW file cannot overwrite the
	// developer's code, so it carries its own, different guards.
	create, err := toolrunner.NewBetaToolFromJSONSchema(
		"create_file",
		"Create a NEW file that does not exist yet. Only for a remediation that "+
			"explicitly prescribes a new class or helper. Never use it to rewrite an existing file.",
		createHandler(root, created))
	if err != nil {
		return nil, err
	}
	return append(tools, edit, create), nil
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
