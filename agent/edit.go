package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	anthropic "github.com/anthropics/anthropic-sdk-go"
)

// editInput is the str_replace edit tool input.
type editInput struct {
	Path      string `json:"path" jsonschema:"required,description=Repository-relative file to edit"`
	OldString string `json:"old_string" jsonschema:"required,description=Exact text to replace; must appear EXACTLY once in the file"`
	NewString string `json:"new_string" jsonschema:"required,description=Replacement text (the secure version)"`
}

// editRecord captures one applied edit, for building the diff.
type editRecord struct {
	Path string
	Old  string
	New  string
}

// cleanRel normalises a repo-relative path for comparison.
func cleanRel(p string) string { return filepath.ToSlash(filepath.Clean(p)) }

// editHandler returns a str_replace edit tool that may edit ONLY allowedPath (the
// located file), applies the change on disk (CWE-22 guarded), and records it.
// old_string must be unique so the edit is unambiguous, mirroring the SDK's
// native Edit tool.
func editHandler(root, allowedPath string, edits *[]editRecord) func(context.Context, editInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
	return func(_ context.Context, in editInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
		zero := anthropic.BetaToolResultBlockParamContentUnion{}
		if cleanRel(in.Path) != cleanRel(allowedPath) {
			return zero, fmt.Errorf("agent: edit is restricted to %s (got %s)", allowedPath, in.Path)
		}
		abs, err := resolveUnderRoot(root, in.Path)
		if err != nil {
			return zero, err
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return zero, err
		}
		content := string(data)
		switch strings.Count(content, in.OldString) {
		case 0:
			return zero, fmt.Errorf("agent: old_string not found in %s", in.Path)
		case 1:
			// unique — proceed
		default:
			return zero, fmt.Errorf("agent: old_string is not unique in %s; include more context", in.Path)
		}
		updated := strings.Replace(content, in.OldString, in.NewString, 1)
		if err := os.WriteFile(abs, []byte(updated), 0o644); err != nil {
			return zero, err
		}
		*edits = append(*edits, editRecord{Path: in.Path, Old: in.OldString, New: in.NewString})
		return textResult("edited " + in.Path), nil
	}
}
