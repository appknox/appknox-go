package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	anthropic "github.com/anthropics/anthropic-sdk-go"
)

// maxCreatedFileBytes caps a single generated file.
//
// A remediation asks for a helper class, not a vendored library. Anything past
// this is the model writing far more than was requested, which the fix contract
// already forbids -- this is the mechanical backstop for it.
const maxCreatedFileBytes = 64 * 1024

// maxCreatedFiles caps how many files one fix may add.
//
// Real remediations name one helper ("introduce a SecureCryptoManager class").
// A fix that wants several is restructuring the project, which is a change for a
// developer to make deliberately, not for autofix to propose in a draft PR.
const maxCreatedFiles = 2

// createInput is the create-file tool input.
type createInput struct {
	Path    string `json:"path" jsonschema:"required,description=New repository-relative file to create; must not already exist"`
	Content string `json:"content" jsonschema:"required,description=Complete contents of the new file"`
}

// createdFile is one file the fix added, captured for delivery.
type createdFile struct {
	Path    string
	Content string
}

// createHandler returns a create-file tool for remediations that prescribe a new
// unit of code rather than an edit to an existing one.
//
// This exists because KnoxIQ remediations routinely ask for one. The Derived
// Crypto Keys guidance on mfva reads "Introduce a new utility class,
// SecureCryptoManager, into your project" and then calls it from the fixed
// method -- a fixer that can only str_replace inside one existing file cannot
// carry that out, so it correctly declined and the finding never cleared.
//
// Guarded rather than open: paths resolve under the repo root (CWE-22), an
// existing file is never overwritten (that is an edit, and edits belong to the
// edit tool, which is restricted to the located file for a reason), and both the
// size and the number of new files are capped.
func createHandler(root string, created *[]createdFile) func(context.Context, createInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
	return func(_ context.Context, in createInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
		zero := anthropic.BetaToolResultBlockParamContentUnion{}
		if len(*created) >= maxCreatedFiles {
			return zero, fmt.Errorf("agent: a fix may add at most %d file(s)", maxCreatedFiles)
		}
		if len(in.Content) > maxCreatedFileBytes {
			return zero, fmt.Errorf("agent: new file %s is %d bytes, over the %d limit",
				in.Path, len(in.Content), maxCreatedFileBytes)
		}
		if strings.TrimSpace(in.Content) == "" {
			return zero, fmt.Errorf("agent: refusing to create empty file %s", in.Path)
		}
		abs, err := resolveUnderRoot(root, in.Path)
		if err != nil {
			return zero, err
		}
		// Never clobber. Overwriting an existing file through the create tool
		// would bypass the edit tool's single-file restriction entirely.
		if _, err := os.Lstat(abs); err == nil {
			return zero, fmt.Errorf("agent: %s already exists; use the edit tool", in.Path)
		} else if !os.IsNotExist(err) {
			return zero, err
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return zero, err
		}
		if err := os.WriteFile(abs, []byte(in.Content), 0o644); err != nil {
			return zero, err
		}
		*created = append(*created, createdFile{Path: cleanRel(in.Path), Content: in.Content})
		return textResult(fmt.Sprintf("created %s (%d bytes)", in.Path, len(in.Content))), nil
	}
}

// removeCreated deletes the files a fix added.
//
// FixFile is side-effect-free by contract: the caller decides whether a fix is
// delivered, so the run must leave the checkout exactly as it found it. A
// created file left behind would be read by the next analysis in the same run as
// if it were the developer's own code.
func removeCreated(root string, created []createdFile) error {
	for _, f := range created {
		abs, err := resolveUnderRoot(root, f.Path)
		if err != nil {
			return err
		}
		if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
