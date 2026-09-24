package helper

import (
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
	if _, err := safeDest(root, rel); err != nil {
		return "", reasonInvalidPath
	}
	// Lstat, not Stat: a symlinked leaf is refused rather than followed.
	info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil || !info.Mode().IsRegular() {
		return "", reasonInvalidPath
	}
	if prunedComponent(root, rel) {
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

// prunedComponent reports whether any directory on rel's path is one the
// locate tools never walk: build output, vendored code, hidden directories,
// nested repositories.
func prunedComponent(root, rel string) bool {
	for dir := path.Dir(rel); dir != "."; dir = path.Dir(dir) {
		if agent.PruneDir(root, filepath.Join(root, filepath.FromSlash(dir))) {
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
