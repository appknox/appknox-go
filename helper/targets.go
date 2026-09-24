package helper

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/appknox/appknox-go/agent"
)

// Target validation (spec 3.2). The locate agent chooses the files; this only
// checks each answer, in order, and records why a target was refused. It never
// adds a file the agent did not name.

const (
	reasonInvalidPath = "invalid path"
	reasonGenerated   = "generated or vendored"
	reasonBuildFile   = "build file (not supported)"
	reasonUnsupported = "unsupported file type"
)

// rejection is a target the agent named that will not be edited, and why.
type rejection struct {
	Path   string
	Reason string
}

// validateTargets returns the accepted targets, cleaned, with duplicates
// merged (a duplicate's why is appended to the first), ordered
// manifest → res → source with the agent's order kept inside each group.
func validateTargets(root string, targets []agent.Target) ([]agent.Target, []rejection) {
	var accepted []agent.Target
	var rejected []rejection
	index := map[string]int{}
	for _, t := range targets {
		rel, reason := checkTarget(root, t.Path)
		if reason != "" {
			rejected = append(rejected, rejection{Path: t.Path, Reason: reason})
			continue
		}
		if i, dup := index[rel]; dup {
			accepted[i] = agent.Target{Path: rel, Why: joinNonEmpty([]string{accepted[i].Why, t.Why}, "; ")}
			continue
		}
		index[rel] = len(accepted)
		accepted = append(accepted, agent.Target{Path: rel, Why: t.Why})
	}
	return orderTargets(accepted), rejected
}

// checkTarget returns the cleaned repo-relative path, or the first reason
// it fails.
func checkTarget(root, raw string) (string, string) {
	rel := filepath.ToSlash(filepath.Clean(strings.TrimSpace(raw)))
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		return "", reasonInvalidPath
	}
	dest, err := safeDest(root, rel)
	if err != nil {
		return "", reasonInvalidPath
	}
	// Lstat, not Stat: a symlinked leaf is refused rather than followed.
	info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil || !info.Mode().IsRegular() {
		return "", reasonInvalidPath
	}
	if prunedComponent(root, dest) {
		return "", reasonGenerated
	}
	if buildFileRE.MatchString(rel) {
		return "", reasonBuildFile
	}
	if !supportedTarget(rel) {
		return "", reasonUnsupported
	}
	return rel, ""
}

// prunedComponent reports whether any directory on the path safeDest actually
// resolved (dest) is one the locate tools never walk: build output, vendored
// code, hidden directories, nested repositories. Using the RESOLVED path,
// rather than the one the agent sent, catches a symlinked directory that
// lands inside a pruned directory even when its own name gives no hint.
// Component names are also compared case-insensitively: agent.PruneDir's own
// check is exact-case, and a compiled app's finding text does not promise to
// preserve the checkout's casing.
func prunedComponent(root, dest string) bool {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	resolvedRoot := resolveDeepest(absRoot)
	rel, err := filepath.Rel(resolvedRoot, dest)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	for dir := path.Dir(rel); dir != "."; dir = path.Dir(dir) {
		abs := filepath.Join(resolvedRoot, filepath.FromSlash(dir))
		if agent.PruneDir(resolvedRoot, abs) {
			return true
		}
		lowerAbs := filepath.Join(filepath.Dir(abs), strings.ToLower(filepath.Base(abs)))
		if agent.PruneDir(resolvedRoot, lowerAbs) {
			return true
		}
	}
	return false
}

// supportedTarget is the set of files a fix call may edit today: Java/Kotlin
// source, the manifest, and resource XML.
func supportedTarget(rel string) bool {
	switch strings.ToLower(path.Ext(rel)) {
	case ".java", ".kt":
		return true
	case ".xml":
		if path.Base(rel) == "AndroidManifest.xml" {
			return true
		}
		for _, part := range strings.Split(path.Dir(rel), "/") {
			if part == "res" {
				return true
			}
		}
	}
	return false
}

// targetRank orders the fan-out: the manifest first, then resources, then
// source, so a later call reads the declarations earlier calls changed.
func targetRank(rel string) int {
	switch {
	case path.Base(rel) == "AndroidManifest.xml":
		return 0
	case strings.EqualFold(path.Ext(rel), ".xml"):
		return 1
	default:
		return 2
	}
}

// orderTargets returns a sorted copy, stable within each rank.
func orderTargets(targets []agent.Target) []agent.Target {
	out := append([]agent.Target(nil), targets...)
	sort.SliceStable(out, func(i, j int) bool {
		return targetRank(out[i].Path) < targetRank(out[j].Path)
	})
	return out
}

// genuinelyNew checks a locate turn's needs_new_file entries against the
// checkout instead of trusting them: the agent decides what a remediation
// needs, but code verifies the claim before a whole finding is skipped on it
// (mfva's live miss: Haiku listed app/proguard-rules.pro and app/build.gradle
// under needs_new_file for an "Application Logs" finding, even though both
// already existed). An entry is NOT new when its name already exists in the
// repo either way: as a literal repo-relative path, or by its base name
// anywhere else in the tree. Everything else is reported genuinely new. The
// repo is walked at most once per call, and only when entries is non-empty.
func genuinelyNew(root string, entries []string) (newOnes []string, notNew []string) {
	if len(entries) == 0 {
		return nil, nil
	}
	names := make([]string, len(entries))
	wantBase := map[string]bool{}
	for i, e := range entries {
		names[i] = needsNewFileName(e)
		wantBase[filepath.Base(names[i])] = true
	}
	foundBase := findBaseNames(root, wantBase)
	for i, e := range entries {
		if existsAsPath(root, names[i]) || foundBase[filepath.Base(names[i])] {
			notNew = append(notNew, e)
			continue
		}
		newOnes = append(newOnes, e)
	}
	return newOnes, notNew
}

// needsNewFileName extracts the file or class name from a needs_new_file
// entry ("<name>: <why>", the shape the locate prompt asks for). An entry
// with no ": " is used whole, trimmed.
func needsNewFileName(entry string) string {
	if i := strings.Index(entry, ": "); i >= 0 {
		return strings.TrimSpace(entry[:i])
	}
	return strings.TrimSpace(entry)
}

// existsAsPath reports whether name, taken as a literal repo-relative path,
// is a regular file on disk. Symlinks are not followed (os.Lstat).
func existsAsPath(root, name string) bool {
	if name == "" || filepath.IsAbs(name) {
		return false
	}
	dest, err := safeDest(root, name)
	if err != nil {
		return false
	}
	info, err := os.Lstat(dest)
	return err == nil && info.Mode().IsRegular()
}

// findBaseNames walks root once, pruning the same directories validation
// prunes (agent.PruneDir), and returns which of wanted's base names exist as
// a regular file anywhere in the tree.
func findBaseNames(root string, wanted map[string]bool) map[string]bool {
	found := map[string]bool{}
	_ = filepath.WalkDir(root, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, never abort the whole walk
		}
		if d.IsDir() {
			if agent.PruneDir(root, abs) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() && wanted[d.Name()] {
			found[d.Name()] = true
		}
		return nil
	})
	return found
}
