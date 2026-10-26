package helper

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/appknox/appknox-go/appknox"
)

// applyResult is what happened to each finding's edits.
type applyResult struct {
	FilesByRef map[string][]string // ref → repo-relative files patched
	Skipped    []appknox.KnoxFixerSkipped
	Files      []string // every patched file
}

type editKey struct{ path, search, replace string }

// replaceOnce applies one search/replace if the search block occurs exactly
// once, trying the file's CRLF line endings when the edit uses LF.
func replaceOnce(content, search, replace string) (string, bool) {
	if strings.Count(content, search) == 1 {
		return strings.Replace(content, search, replace, 1), true
	}
	if strings.Contains(content, "\r\n") && !strings.Contains(search, "\r\n") {
		crlfSearch := strings.ReplaceAll(search, "\n", "\r\n")
		if strings.Count(content, crlfSearch) == 1 {
			return strings.Replace(content, crlfSearch, strings.ReplaceAll(replace, "\n", "\r\n"), 1), true
		}
	}
	return content, false
}

// applyEdits applies each finding's edits as a unit: if any edit of a finding
// doesn't match exactly once, none of that finding's edits are kept. The
// same edit sent for two findings (e.g. two findings fixed by one line) is
// applied once and counted for both.
func applyEdits(root string, edits []appknox.KnoxFixerEdit) (*applyResult, map[string]string, error) {
	res := &applyResult{FilesByRef: map[string][]string{}}
	var refs []string
	byRef := map[string][]appknox.KnoxFixerEdit{}
	for _, e := range edits {
		if _, ok := byRef[e.Ref]; !ok {
			refs = append(refs, e.Ref)
		}
		byRef[e.Ref] = append(byRef[e.Ref], e)
	}
	original := map[string]string{} // path → content before any edit
	current := map[string]string{}
	applied := map[editKey]bool{}
	read := func(rel string) (string, error) {
		if c, ok := current[rel]; ok {
			return c, nil
		}
		abs, err := absRepoPath(root, rel)
		if err != nil {
			return "", err
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return "", err
		}
		original[rel], current[rel] = string(data), string(data)
		return current[rel], nil
	}

	for _, ref := range refs {
		staged := map[string]string{}
		var files []string
		reason := ""
		var newlyApplied []editKey
		for _, e := range byRef[ref] {
			key := editKey{e.Path, e.Search, e.Replace}
			if !isEditableRepoFile(e.Path) {
				reason = "edit targets a protected file"
				break
			}
			if applied[key] {
				files = appendUnique(files, e.Path)
				continue
			}
			content, ok := staged[e.Path]
			if !ok {
				var err error
				if content, err = read(e.Path); err != nil {
					reason = "file could not be read"
					break
				}
			}
			updated, matched := replaceOnce(content, e.Search, e.Replace)
			if !matched {
				reason = "edit did not match the current code"
				break
			}
			staged[e.Path] = updated
			files = appendUnique(files, e.Path)
			newlyApplied = append(newlyApplied, key)
		}
		if reason != "" {
			res.Skipped = append(res.Skipped, appknox.KnoxFixerSkipped{Ref: ref, Reason: reason})
			continue
		}
		for p, c := range staged {
			current[p] = c
		}
		for _, k := range newlyApplied {
			applied[k] = true
		}
		res.FilesByRef[ref] = files
	}

	for rel, content := range current {
		if content == original[rel] {
			continue
		}
		if err := writeRepoFile(root, rel, content); err != nil {
			return nil, original, err
		}
		res.Files = append(res.Files, rel)
	}
	sort.Strings(res.Files)
	return res, original, nil
}

func writeRepoFile(root, rel, content string) error {
	abs, err := absRepoPath(root, rel)
	if err != nil {
		return err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return err
	}
	return os.WriteFile(abs, []byte(content), info.Mode().Perm())
}

func appendUnique(list []string, value string) []string {
	for _, v := range list {
		if v == value {
			return list
		}
	}
	return append(list, value)
}

// runVerify runs the customer's own verify command (e.g. a compile task).
func runVerify(ctx context.Context, dir, command string) bool {
	if command == "" {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run() == nil
}

// verifyAndRevert: if the verify command fails with all fixes applied, keep
// fixes one finding at a time and revert those that break the build.
func verifyAndRevert(ctx context.Context, root, command string, edits []appknox.KnoxFixerEdit, res *applyResult, original map[string]string) (*applyResult, error) {
	if command == "" || len(res.Files) == 0 || runVerify(ctx, root, command) {
		return res, nil
	}
	for rel, content := range original {
		if err := writeRepoFile(root, rel, content); err != nil {
			return nil, err
		}
	}
	var refs []string
	for ref := range res.FilesByRef {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	var kept []appknox.KnoxFixerEdit
	out := &applyResult{FilesByRef: map[string][]string{}, Skipped: res.Skipped}
	for _, ref := range refs {
		var candidate []appknox.KnoxFixerEdit
		candidate = append(candidate, kept...)
		for _, e := range edits {
			if e.Ref == ref {
				candidate = append(candidate, e)
			}
		}
		trial, trialOriginal, err := applyEdits(root, candidate)
		if err != nil {
			return nil, err
		}
		if _, ok := trial.FilesByRef[ref]; ok && runVerify(ctx, root, command) {
			kept = candidate
		} else {
			out.Skipped = append(out.Skipped, appknox.KnoxFixerSkipped{Ref: ref, Reason: "verify command failed with this fix"})
		}
		for rel, content := range trialOriginal {
			if err := writeRepoFile(root, rel, content); err != nil {
				return nil, err
			}
		}
	}
	final, _, err := applyEdits(root, kept)
	if err != nil {
		return nil, err
	}
	final.Skipped = append(out.Skipped, final.Skipped...)
	return final, nil
}
