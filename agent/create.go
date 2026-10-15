package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	sdk "github.com/anthropics/anthropic-sdk-go"
)

// createInput is the create_file tool input.
type createInput struct {
	Path    string `json:"path" jsonschema:"required,description=Repository-relative path of the NEW file (must not exist yet)"`
	Content string `json:"content" jsonschema:"required,description=The complete content of the new file"`
}

// createHandler returns a create_file tool that may create ONLY allowedPath,
// and only when nothing is there yet: it never overwrites, so a model that
// misjudged a file as new cannot clobber the real one. Missing parent
// directories are created; the path is resolved under root first (CWE-22 /
// CWE-59), and the leaf is opened O_EXCL so a file or symlink appearing in
// between is refused rather than followed. Later changes to the new file go
// through the ordinary edit tool.
func createHandler(root, allowedPath string, edits *[]editRecord) func(context.Context, createInput) (sdk.BetaToolResultBlockParamContentUnion, error) {
	return func(_ context.Context, in createInput) (sdk.BetaToolResultBlockParamContentUnion, error) {
		zero := sdk.BetaToolResultBlockParamContentUnion{}
		if cleanRel(in.Path) != cleanRel(allowedPath) {
			return zero, fmt.Errorf("agent: create_file is restricted to %s (got %s)", allowedPath, in.Path)
		}
		abs, err := resolveUnderRoot(root, in.Path)
		if err != nil {
			return zero, err
		}
		if _, err := os.Lstat(abs); err == nil {
			return zero, fmt.Errorf("agent: %s already exists; use the edit tool to change it", in.Path)
		}
		// resolveUnderRoot can only canonicalise a parent that exists. Check
		// the deepest ancestor that does BEFORE MkdirAll follows it, and the
		// full parent again after, so a symlinked ancestor cannot take even
		// an empty directory, let alone the file, outside the repository.
		if err := parentStillUnderRoot(root, abs); err != nil {
			return zero, err
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return zero, err
		}
		if err := parentStillUnderRoot(root, abs); err != nil {
			return zero, err
		}
		f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return zero, err
		}
		_, writeErr := f.WriteString(in.Content)
		if closeErr := f.Close(); writeErr == nil {
			writeErr = closeErr
		}
		if writeErr != nil {
			return zero, writeErr
		}
		*edits = append(*edits, editRecord{Path: in.Path, New: in.Content})
		return textResult("created " + in.Path), nil
	}
}

// parentStillUnderRoot resolves the deepest existing ancestor of abs through
// every symlink and refuses it unless it is inside root.
func parentStillUnderRoot(root, abs string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	for {
		if _, statErr := os.Lstat(dir); statErr == nil || filepath.Dir(dir) == dir {
			break
		}
		dir = filepath.Dir(dir)
	}
	parent, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	if !underRoot(canonicalDir(absRoot), parent) {
		return fmt.Errorf("agent: %s resolves outside the repository root", abs)
	}
	return nil
}

// missingDirs returns the directories between abs's deepest existing ancestor
// and abs itself (deepest first), i.e. what creating abs would add. Recorded
// before a create run so the revert removes exactly those, and nothing that
// already existed.
func missingDirs(abs string) []string {
	var dirs []string
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return dirs
		}
		dirs = append(dirs, dir)
		if filepath.Dir(dir) == dir {
			return dirs
		}
	}
}

// removeCreated deletes a file the create run made and the directories it
// had to add, deepest first. A directory that is no longer empty is left in
// place, and so is every one above it: something else lives there now. Any
// other failure is returned.
func removeCreated(abs string, dirs []string) error {
	if err := os.Remove(abs); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, d := range dirs {
		err := os.Remove(d)
		switch {
		case err == nil, errors.Is(err, fs.ErrNotExist):
		case errors.Is(err, syscall.ENOTEMPTY), errors.Is(err, syscall.EEXIST):
			return nil
		default:
			return err
		}
	}
	return nil
}
