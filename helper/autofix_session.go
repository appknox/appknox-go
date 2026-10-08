package helper

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/workspace"
)

// The CLI side of an autofix job. Appknox decides what to read and what to
// change; this executes those calls on the checkout and answers with what it
// found. Every check that needs the repository runs here and nowhere else:
// target validation, the static patch gate, and the all-or-nothing rollback of
// a finding. No prompt, remediation or model reaches this process.

// Tool calls Appknox sends. The first five come from the model; the rest are
// asked for between model turns.
const (
	toolReadFile        = "read_file"
	toolGrep            = "grep"
	toolGlob            = "glob"
	toolEdit            = "edit"
	toolCreateFile      = "create_file"
	toolProjectProfile  = "project_profile"
	toolValidateTargets = "validate_targets"
	toolBeginTarget     = "begin_target"
	toolVerifyTarget    = "verify_target"
	toolFinishUnit      = "finish_unit"
)

// fixTarget is the one file the current fix turn may change.
type fixTarget struct {
	path   string
	create bool
	before string // content when the turn began; "" for a new file
}

// fixUnit is the KnoxIQ finding being fixed: what each file held before the
// finding touched it, so the finding can be undone as a whole.
type fixUnit struct {
	id         string
	before     map[string]string
	patchStart int // index of the unit's first patch in autofixSession.patches
}

// verdict is what the last verify_target decided, for a finish_unit sent in
// the same batch.
type verdict struct {
	path     string
	create   bool
	changed  bool
	accepted bool
	rule     string // the gate rule that refused the patch, if any
}

// autofixSession executes one job's tool calls against root.
type autofixSession struct {
	root        string
	work        *workingTree
	target      *fixTarget
	unit        *fixUnit
	lastVerdict *verdict
	patches     []filePatch
}

func newAutofixSession(root string) *autofixSession {
	return &autofixSession{root: root, work: newWorkingTree(root)}
}

// runAll answers one step's calls in order. A call that fails is reported to
// Appknox as an error result; it never stops the others.
func (s *autofixSession) runAll(calls []appknox.AutofixToolCall) []appknox.AutofixToolResult {
	out := make([]appknox.AutofixToolResult, 0, len(calls))
	for _, call := range calls {
		content, data, err := s.run(call)
		res := appknox.AutofixToolResult{ID: call.ID, Content: content, Data: data}
		if err != nil {
			res = appknox.AutofixToolResult{ID: call.ID, Content: err.Error(), IsError: true}
		}
		out = append(out, res)
	}
	return out
}

func (s *autofixSession) run(call appknox.AutofixToolCall) (string, map[string]interface{}, error) {
	args := call.Args
	switch call.Name {
	case toolReadFile:
		text, err := workspace.ReadFile(s.root, strArg(args, "path"))
		return text, nil, err
	case toolGrep:
		text, err := workspace.Grep(s.root, strArg(args, "pattern"))
		return text, nil, err
	case toolGlob:
		return workspace.Glob(s.root, strArg(args, "pattern")), nil, nil
	case toolEdit:
		return s.edit(args)
	case toolCreateFile:
		return s.createFile(args)
	case toolProjectProfile:
		// Facts read off the build files; the fixer sees one file at a time
		// and could not derive them.
		return "", map[string]interface{}{"profile": describeBuild(s.root).String()}, nil
	case toolValidateTargets:
		return s.validateTargets(args)
	case toolBeginTarget:
		return s.beginTarget(args)
	case toolVerifyTarget:
		return s.verifyTarget(args)
	case toolFinishUnit:
		return s.finishUnit(args)
	}
	return "", nil, fmt.Errorf("unknown tool %q", call.Name)
}

func (s *autofixSession) edit(args map[string]interface{}) (string, map[string]interface{}, error) {
	if s.target == nil {
		return "", nil, errors.New("no file is open for editing")
	}
	path := strArg(args, "path")
	if err := workspace.Edit(s.root, s.target.path, path,
		strArg(args, "old_string"), strArg(args, "new_string")); err != nil {
		return "", nil, err
	}
	return "edited " + path, nil, nil
}

func (s *autofixSession) createFile(args map[string]interface{}) (string, map[string]interface{}, error) {
	if s.target == nil || !s.target.create {
		return "", nil, errors.New("no new file is open for creation")
	}
	path := strArg(args, "path")
	if err := workspace.CreateFile(s.root, s.target.path, path, strArg(args, "content")); err != nil {
		return "", nil, err
	}
	return "created " + path, nil, nil
}

// validateTargets checks the locate turn's answer against the checkout and
// either skips the whole finding or hands back the targets to fix, in
// manifest → res → source order. It never adds a file the answer did not name.
func (s *autofixSession) validateTargets(args map[string]interface{}) (string, map[string]interface{}, error) {
	s.unit = &fixUnit{id: strArg(args, "unit_id"), before: map[string]string{}, patchStart: len(s.patches)}
	targets := targetsArg(args, "targets")
	notFound := stringsArg(args, "not_found")
	needsNew := stringsArg(args, "needs_new_file")
	skip := func(detail string, results []targetResult) (string, map[string]interface{}, error) {
		return "", map[string]interface{}{"skip": true, "status": statusSkipped, "detail": detail,
			"results": asData(results)}, nil
	}

	created, existing, badNew := validateNewFiles(s.root, targetsArg(args, "new_files"))
	// A file listed under both new_files and needs_new_file is placed: it is
	// created, not a reason to skip the finding.
	needsNew = withoutNamed(needsNew, created)
	var extraNotes []string
	if len(needsNew) > 0 {
		// The claim is checked against the checkout before a whole finding is
		// skipped on it: build files that already exist get listed here too.
		newOnes, notNew := genuinelyNew(s.root, needsNew)
		if len(newOnes) > 0 {
			return skip(reasonNeedsNewFile+": "+strings.Join(newOnes, "; "), nil)
		}
		extraNotes = notNewNotes(notNew)
	}
	if len(badNew) > 0 {
		// The rest of the remediation refers to the file it creates, so none
		// of it may land without it.
		return skip(reasonNewFileRejected+": "+rejectionList(badNew), nil)
	}
	accepted, rejected := validateTargets(s.root, append(withoutPaths(targets, created), existing...))
	if bad := unanchoredNewFiles(created, accepted); len(bad) > 0 {
		return skip(reasonNewFileRejected+": "+rejectionList(bad), nil)
	}
	accepted = orderTargets(append(created, accepted...))
	results := rejectionResults(rejected)
	notes := append(notFoundNotes(notFound), extraNotes...)
	if boolArg(args, "third_party") && len(accepted) == 0 {
		// The library is the only place the fix could go, and it is not the
		// customer's to patch.
		return skip(joinNonEmpty([]string{reasonThirdPartyNoSource, unpatchedDetail(results, notes)}, "; "), results)
	}
	return "", map[string]interface{}{"accepted": asData(accepted), "results": asData(results),
		"notes": asData(notes)}, nil
}

// beginTarget opens one file for a fix turn and remembers its content, so the
// turn can be judged and undone.
func (s *autofixSession) beginTarget(args map[string]interface{}) (string, map[string]interface{}, error) {
	if s.unit == nil {
		return "", nil, errors.New("begin_target before validate_targets")
	}
	path := workspace.CleanRel(strArg(args, "path"))
	create := boolArg(args, "new")
	before, err := readUnderRoot(s.root, path)
	switch {
	case err == nil && create:
		return "", nil, fmt.Errorf("%s already exists; it is not a new file", path)
	case err != nil && !(create && errors.Is(err, fs.ErrNotExist)):
		return "", nil, err
	}
	if err := s.work.track(path); err != nil {
		return "", nil, err
	}
	if _, seen := s.unit.before[path]; !seen {
		s.unit.before[path] = before
	}
	s.target = &fixTarget{path: path, create: create, before: before}
	return "", map[string]interface{}{}, nil
}

// verifyTarget closes the fix turn: it holds the change to the static patch
// gate and keeps it, or puts the file back and says why. With discard set (the
// turn failed) the file is put back unconditionally.
//
// The gate runs with the original on disk, as it always has, so a check that
// scans the repository judges the patch against the code it replaces.
func (s *autofixSession) verifyTarget(args map[string]interface{}) (string, map[string]interface{}, error) {
	t := s.target
	path := workspace.CleanRel(strArg(args, "path"))
	s.lastVerdict = nil
	if t == nil || t.path != path {
		return "", nil, fmt.Errorf("%s is not the file being fixed", path)
	}
	s.target = nil
	patched, err := readUnderRoot(s.root, path)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", nil, err
	}
	changed := exists && (t.create || patched != t.before)
	if err := s.revert(t); err != nil {
		return "", nil, err
	}
	if boolArg(args, "discard") || !changed {
		s.lastVerdict = &verdict{path: path, create: t.create}
		return "", map[string]interface{}{"changed": false}, nil
	}
	if v := verifyPatch(s.root, path, t.before, patched); v != nil {
		fmt.Printf("   .. %s rejected (%s)\n", path, v.Rule)
		s.lastVerdict = &verdict{path: path, create: t.create, changed: true, rule: v.Rule}
		return "", map[string]interface{}{"changed": true, "accepted": false,
			"violation": map[string]interface{}{"rule": v.Rule, "detail": v.Detail}}, nil
	}
	if err := applyPatch(s.root, path, patched); err != nil {
		return "", nil, err
	}
	s.lastVerdict = &verdict{path: path, create: t.create, changed: true, accepted: true}
	patch := filePatch{Path: path, Content: patched, Diff: unifiedDiff(path, t.before, patched),
		Finding: s.unit.id}
	if !t.create {
		patch.Formatting = formattingAdvice(path, t.before, patched)
	}
	s.patches = append(s.patches, patch)
	return "", map[string]interface{}{"changed": true, "accepted": true}, nil
}

// revert puts the open file back as the turn found it.
func (s *autofixSession) revert(t *fixTarget) error {
	if t.create {
		return s.work.remove(t.path)
	}
	return applyPatch(s.root, t.path, t.before)
}

// finishUnit closes a finding. A finding that must land whole -- one that
// edits a module build script, or creates a file -- and did not, is undone:
// every file it patched goes back to what it held before the finding.
//
// With after_verify, finish_unit rides in the same batch as the last target's
// verify_target, so that target's result is taken from the verdict just
// given. When that verdict calls for a retry, the finding is not finished:
// the answer is "deferred" and the unit stays open.
func (s *autofixSession) finishUnit(args map[string]interface{}) (string, map[string]interface{}, error) {
	u := s.unit
	if u == nil {
		return "", nil, errors.New("finish_unit before validate_targets")
	}
	var results []targetResult
	if err := fromData(args["results"], &results); err != nil {
		return "", nil, fmt.Errorf("finish_unit results: %w", err)
	}
	if boolArg(args, "after_verify") {
		v := s.lastVerdict
		if v == nil {
			return "", nil, errors.New("finish_unit: the verify it follows did not complete")
		}
		if v.rule != "" && boolArg(args, "retry_allowed") {
			return "", map[string]interface{}{"deferred": true}, nil
		}
		results = append(results, verdictResult(v, strArg(args, "refused")))
	}
	s.unit = nil
	if needsRollback(results) {
		for _, r := range results {
			if !r.Patched {
				continue
			}
			if r.New {
				if err := s.work.remove(r.Path); err != nil {
					return "", nil, fmt.Errorf("rolling back new file %s: %w", r.Path, err)
				}
				continue
			}
			before, ok := u.before[r.Path]
			if !ok {
				return "", nil, fmt.Errorf("cannot roll back %s: its content before the fix was not read", r.Path)
			}
			if err := applyPatch(s.root, r.Path, before); err != nil {
				return "", nil, fmt.Errorf("rolling back %s: %w", r.Path, err)
			}
		}
		s.patches = s.patches[:u.patchStart]
		results = rolledBack(results)
	}
	return "", map[string]interface{}{"results": asData(results)}, nil
}

// verdictResult turns a final verdict into the target's result line. The
// reasons are the ones Appknox gives when it records a verify itself.
func verdictResult(v *verdict, refused string) targetResult {
	r := targetResult{Path: v.path, New: v.create}
	switch {
	case v.accepted:
		r.Patched = true
	case v.rule != "":
		r.Reason = "rejected by patch gate (" + v.rule + ")"
	case refused != "":
		// After a refusal this is still a refusal: the file needed a change
		// the gate would not allow, which is not the same as needing none.
		r.Reason = "rejected by patch gate (" + refused + "), then declined"
	default:
		r.Reason = "declined: no edit made"
	}
	return r
}

// result is every file the job changed, one patch per path.
func (s *autofixSession) result() []filePatch {
	return lastPatchPerPath(s.patches, s.work.original)
}

// needsRollback reports whether a unit must be undone as a whole:
//   - it patched a module build script or rules file while another target was
//     refused by the gate or failed; or
//   - it creates a file, and that file was not created, or any target was
//     refused or failed, or no existing file was changed to use it -- the new
//     file and the edits that refer to it are one change; or
//   - the gate refused its module build-script change (even when the retry
//     then declined) and anything else was changed: the rest may rely on it.
//
// A declined EXISTING target alone triggers none: it needed no change.
func needsRollback(results []targetResult) bool {
	script, hasNew, failed, usedBy, scriptRefused := false, false, false, false, false
	for _, r := range results {
		refused := strings.HasPrefix(r.Reason, "rejected by patch gate")
		scriptRefused = scriptRefused || (!r.Patched && refused && isModuleBuildScript(r.Path))
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
		if !r.Patched && (refused || strings.HasPrefix(r.Reason, "error:")) {
			failed = true
		}
	}
	return (script && failed) || (hasNew && (failed || !usedBy)) || (scriptRefused && (usedBy || hasNew))
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

// withoutPaths drops targets naming a file listed as new: the model sometimes
// lists a new file under targets too, where it would be refused as missing.
func withoutPaths(ts, drop []workspace.Target) []workspace.Target {
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d.Path] = true
	}
	out := make([]workspace.Target, 0, len(ts))
	for _, t := range ts {
		if !skip[filepath.ToSlash(filepath.Clean(strings.TrimSpace(t.Path)))] {
			out = append(out, t)
		}
	}
	return out
}

// withoutNamed drops needs_new_file entries that name a file already placed
// in created, by path or by base name ("network_security_config.xml: ...").
func withoutNamed(entries []string, created []workspace.Target) []string {
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
// source set (<module>/src/<set>/) as any existing target. Anywhere else, the
// gate's on-disk check passes while the build does not.
func unanchoredNewFiles(created, existing []workspace.Target) []rejection {
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

// Tool-call arguments arrive as decoded JSON.

func strArg(args map[string]interface{}, key string) string {
	s, _ := args[key].(string)
	return s
}

func boolArg(args map[string]interface{}, key string) bool {
	b, _ := args[key].(bool)
	return b
}

func stringsArg(args map[string]interface{}, key string) []string {
	var out []string
	_ = fromData(args[key], &out)
	return out
}

func targetsArg(args map[string]interface{}, key string) []workspace.Target {
	var out []workspace.Target
	_ = fromData(args[key], &out)
	return out
}

// fromData decodes a JSON-shaped value into out.
func fromData(v interface{}, out interface{}) error {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// asData turns a typed value into its JSON shape, for a result's data.
func asData(v interface{}) interface{} {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out interface{}
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		return []interface{}{}
	}
	return out
}
