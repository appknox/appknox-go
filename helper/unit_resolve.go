package helper

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/appknox/appknox-go/agent"
)

// The unit resolve pass (spec 3.4) and completion (spec 3.5). After a unit's
// targets are fixed, every resource, R reference and manifest component class
// its patched files introduce must be defined somewhere. Whatever is not
// gets a completion target -- the file that should define it -- fixed like
// any other target. A reference whose completion declined is inlined by
// re-fixing the file that makes it. A unit still unresolved after
// maxCompletionRounds rolls back: a broken build is never delivered.

const maxCompletionRounds = 2

// unresolvedRef is a reference nothing in the repository defines.
type unresolvedRef struct {
	Kind string // resource kind, or "class"
	Name string // resource name, or fully qualified class name
	From string // the repository-relative file that references it
}

func (r unresolvedRef) String() string {
	switch {
	case r.Kind == "class":
		return r.Name
	case strings.HasSuffix(r.From, ".java") || strings.HasSuffix(r.From, ".kt"):
		return "R." + r.Kind + "." + r.Name
	}
	return "@" + r.Kind + "/" + r.Name
}

// unresolvedUnitRefs returns what the patched files introduce, relative to
// before (a file absent from before is new, compared against ""), that a
// fresh index of the checkout does not define. Each reference appears once.
func unresolvedUnitRefs(root string, patched []string, before map[string]string) []unresolvedRef {
	var refs []unresolvedRef
	for _, p := range patched {
		content, err := readUnderRoot(root, p)
		if err != nil {
			continue
		}
		orig := before[p]
		for _, r := range introducedResourceRefs(p, orig, content) {
			refs = append(refs, unresolvedRef{Kind: r.Kind, Name: r.Name, From: p})
		}
		for _, r := range introducedRRefs(root, p, orig, content) {
			refs = append(refs, unresolvedRef{Kind: r.Kind, Name: r.Name, From: p})
		}
		for _, fqcn := range addedComponentClasses(root, p, orig, content) {
			refs = append(refs, unresolvedRef{Kind: "class", Name: fqcn, From: p})
		}
	}
	if len(refs) == 0 {
		return nil
	}
	idx := buildResourceIndex(root)
	seen := map[string]bool{}
	var out []unresolvedRef
	for _, r := range refs {
		key, defined := "class/"+r.Name, idx.hasClass(r.Name)
		if r.Kind != "class" {
			key, defined = resKey(r.Kind, r.Name), idx.has(r.Kind, r.Name)
		}
		if defined || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}

// valuesFiles is where a completion defines each values kind.
var valuesFiles = map[string]string{
	"string": "strings.xml", "plurals": "strings.xml", "dimen": "dimens.xml", "fraction": "dimens.xml",
	"color": "colors.xml", "bool": "bools.xml", "integer": "integers.xml", "array": "arrays.xml",
	"style": "styles.xml", "id": "ids.xml",
}

// completionFileKinds are file resources a completion may create as one new
// XML file. raw, mipmap and interpolator are not: they need a binary or a
// directory checkNewTarget refuses.
var completionFileKinds = map[string]bool{"layout": true, "xml": true, "drawable": true, "menu": true,
	"anim": true, "animator": true, "navigation": true, "transition": true, "font": true}

// completionTarget is the file that should define r, in the main source set
// of the module holding the file that references it. It passes the same
// validation as a locate turn's new_files, so a NEW file under an
// Eclipse-layout <module>/res is refused and its reference inlined instead.
func completionTarget(root string, r unresolvedRef) (agent.Target, bool) {
	module := moduleRoot(root, r.From)
	if module == "" {
		return agent.Target{}, false
	}
	res := moduleResDir(root, module)
	var rel, why string
	switch {
	case r.Kind == "class":
		rel = classPath(root, module, r.Name)
		why = fmt.Sprintf("completion: create class %s, which %s declares; write it as the remediation describes", r.Name, r.From)
	case r.Kind == "id":
		rel = path.Join(res, "values", valuesFiles[r.Kind])
		why = fmt.Sprintf(`completion: define %s, which %s references; add only <item type="id" name="%s"/>`,
			r, r.From, r.Name)
	case valuesFiles[r.Kind] != "":
		rel = path.Join(res, "values", valuesFiles[r.Kind])
		why = fmt.Sprintf("completion: define %s, which %s references; add only that entry", r, r.From)
	case completionFileKinds[r.Kind]:
		rel = path.Join(res, r.Kind, r.Name+".xml")
		why = fmt.Sprintf("completion: create %s, which %s references", r, r.From)
	default:
		return agent.Target{}, false
	}
	got, reason := checkNewTarget(root, rel)
	switch reason {
	case "":
		return agent.Target{Path: got, Why: why, New: true}, true
	case reasonNewExists:
		return agent.Target{Path: got, Why: why}, true
	}
	return agent.Target{}, false
}

// moduleResDir is the module's main res directory the build reads:
// <module>/src/main/res when it exists, else an Eclipse-layout <module>/res
// (res.srcDirs = ['res']) when that exists, else <module>/src/main/res.
func moduleResDir(root, module string) string {
	for _, dir := range []string{path.Join(module, "src", "main", "res"), path.Join(module, "res")} {
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(dir))); err == nil && info.IsDir() {
			return dir
		}
	}
	return path.Join(module, "src", "main", "res")
}

// classPath places a new class in the module's language: Kotlin when the
// module's main set already has a .kt file (under kotlin/ when that directory
// exists), Java otherwise.
func classPath(root, module, fqcn string) string {
	dir, ext := "java", ".java"
	if moduleUsesKotlin(root, module) {
		ext = ".kt"
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(module), "src", "main", "kotlin")); err == nil && info.IsDir() {
			dir = "kotlin"
		}
	}
	return path.Join(module, "src", "main", dir, strings.ReplaceAll(fqcn, ".", "/")+ext)
}

func moduleUsesKotlin(root, module string) bool {
	found := false
	_ = filepath.Walk(filepath.Join(root, filepath.FromSlash(module), "src", "main"),
		func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if strings.HasSuffix(p, ".kt") {
				found = true
				return filepath.SkipAll
			}
			return nil
		})
	return found
}

// completionTargets maps refs to their completion targets, one per file,
// with the Why of every ref that file defines. Refs with no target are left
// to inlining.
func completionTargets(root string, refs []unresolvedRef) []agent.Target {
	var out []agent.Target
	at := map[string]int{}
	for _, r := range refs {
		t, ok := completionTarget(root, r)
		if !ok {
			continue
		}
		if i, dup := at[t.Path]; dup {
			out[i].Why += "; " + t.Why
			continue
		}
		at[t.Path] = len(out)
		out = append(out, t)
	}
	return out
}

type referrer struct {
	from string
	refs []unresolvedRef
}

// byReferrer groups refs by the file that makes them, in path order.
func byReferrer(refs []unresolvedRef) []referrer {
	group := map[string][]unresolvedRef{}
	for _, r := range refs {
		group[r.From] = append(group[r.From], r)
	}
	out := make([]referrer, 0, len(group))
	for from, rs := range group {
		out = append(out, referrer{from: from, refs: rs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].from < out[j].from })
	return out
}

// inlinable drops the refs a re-fix cannot replace with a literal: ids.
func inlinable(refs []unresolvedRef) []unresolvedRef {
	out := make([]unresolvedRef, 0, len(refs))
	for _, r := range refs {
		if r.Kind != "id" {
			out = append(out, r)
		}
	}
	return out
}

// inlinePrior is what the re-fix of a referencing file is told.
func inlinePrior(refs []unresolvedRef) string {
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.Kind == "class" {
			parts = append(parts, fmt.Sprintf("class %s does not exist and could not be created: "+
				"declare no component for it", r.Name))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s is not defined anywhere and could not be created: "+
			"write its literal value in place instead", r))
	}
	return strings.Join(parts, "; ")
}

// unresolvedReason is the rollback reason for a unit left unresolved.
func unresolvedReason(left []unresolvedRef, rounds int) string {
	names := make([]string, 0, len(left))
	for _, r := range left {
		names = append(names, r.String())
	}
	if rounds == 0 {
		return "rolled back: unresolved " + strings.Join(names, ", ") + "; the run stopped before completion"
	}
	return fmt.Sprintf("rolled back: unresolved %s after %d completion rounds", strings.Join(names, ", "), rounds)
}

// patchedPaths lists each patched path once, in order.
func patchedPaths(results ...[]targetResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, rs := range results {
		for _, r := range rs {
			if r.Patched && !seen[r.Path] {
				seen[r.Path] = true
				out = append(out, r.Path)
			}
		}
	}
	return out
}

// createdByUnit reports whether the unit's own targets created path.
func createdByUnit(results []targetResult, path string) bool {
	for _, r := range results {
		if r.Path == path && r.New && r.Patched {
			return true
		}
	}
	return false
}

// unitCreated reports whether the unit already created path itself -- by one
// of its own original targets, or by an earlier completion round. Fix round
// 1: a completion target that checkNewTarget now reports as reasonNewExists
// (because THIS unit created it, in this round or an earlier one) must still
// be treated as new, or its "before" content gets recorded as whatever this
// unit itself just wrote -- hiding a reference that file introduces from
// unresolvedUnitRefs, and later making rollBack resurrect it from that stale
// content instead of deleting it (spec 3.5).
func unitCreated(results, done []targetResult, path string) bool {
	return createdByUnit(results, path) || createdByUnit(done, path)
}

// whyOf is the locate turn's reason for path, or "".
func whyOf(all []agent.Target, path string) string {
	for _, t := range all {
		if t.Path == path {
			return t.Why
		}
	}
	return ""
}

// upsertPatch returns patches with p in place of any earlier patch to its
// path. When there IS an earlier patch, p's Diff is recomputed from the
// path's pre-unit content (before[p.Path] -- "" both when the path is
// absent from before and when it was genuinely empty, and "" is exactly
// right for a path this unit created) to p's final content, the same way
// autofix.go's collapsedPatch recomputes a multi-patch path's diff from its
// true original to its final state (see unifiedDiff there). Without this, a
// path fixed more than once in one unit -- a new file re-fixed after its
// completion declined, a completion target itself completed again -- would
// report only its LAST call's hunk instead of the whole change (fix round 1).
// A path with no earlier patch keeps its own Diff, which already covers its
// one true pre-call state.
func upsertPatch(patches []filePatch, p filePatch, before map[string]string) []filePatch {
	out := make([]filePatch, 0, len(patches)+1)
	replaced := false
	for _, q := range patches {
		if q.Path == p.Path {
			replaced = true
			continue
		}
		out = append(out, q)
	}
	if replaced {
		if d := unifiedDiff(p.Path, before[p.Path], p.Content); d != "" {
			p.Diff = d
		}
	}
	return append(out, p)
}

// completeUnit runs up to maxCompletionRounds of resolve-and-complete over a
// unit whose targets are fixed. It returns the unit's patches (completion and
// re-fix patches folded in), the completion targets' results, and what is
// still unresolved after the last round. It records each completion target's
// content before its fix in before, for rollBack. The error is a run-stopping
// one from fixOne (gateway budget, the manual path).
func (s fixSession) completeUnit(ctx context.Context, in FindingInputs, u FindingUnit, all []agent.Target,
	results []targetResult, patches []filePatch, before map[string]string,
) ([]filePatch, []targetResult, []unresolvedRef, error) {
	var done []targetResult
	for round := 0; round < maxCompletionRounds; round++ {
		refs := unresolvedUnitRefs(s.root, patchedPaths(results, done), before)
		if len(refs) == 0 {
			return patches, done, nil, nil
		}
		for _, t := range completionTargets(s.root, refs) {
			created := t.New || unitCreated(results, done, t.Path)
			if !created {
				if _, known := before[t.Path]; !known {
					if content, err := readUnderRoot(s.root, t.Path); err == nil {
						before[t.Path] = content
					}
				}
			}
			tr, patch, err := s.fixOne(ctx, in, u, t, all, "")
			tr.New = created
			tr.Completion = true
			done = append(done, tr)
			if patch != nil {
				patches = upsertPatch(patches, *patch, before)
			}
			if err != nil {
				return patches, done, refs, err
			}
		}
		// What completion did not define is inlined where it is referenced;
		// an id has no literal value, so it is left to the next round.
		for _, g := range byReferrer(inlinable(unresolvedUnitRefs(s.root, patchedPaths(results, done), before))) {
			t := agent.Target{Path: g.from, Why: whyOf(all, g.from)}
			_, patch, err := s.fixOne(ctx, in, u, t, all, inlinePrior(g.refs))
			if patch != nil {
				patches = upsertPatch(patches, *patch, before)
			}
			if err != nil {
				return patches, done, g.refs, err
			}
		}
	}
	return patches, done, unresolvedUnitRefs(s.root, patchedPaths(results, done), before), nil
}

// landed drops completion targets that made no edit: their reference was
// inlined instead, and a declined completion is not a failure of the unit.
func landed(results []targetResult) []targetResult {
	out := make([]targetResult, 0, len(results))
	for _, r := range results {
		if r.Completion && !r.Patched {
			continue
		}
		out = append(out, r)
	}
	return out
}
