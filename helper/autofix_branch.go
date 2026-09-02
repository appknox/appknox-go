package helper

import (
	"os"
	"regexp"
	"strings"
)

// Branch and PR identity.
//
// One active autofix branch and one draft PR PER SOURCE FEATURE BRANCH, per the
// agreed architecture. Keying on the analysis or the scan instead produces a new
// branch and a new PR for every build of the same branch, which is PR sprawl:
// the developer ends up triaging remediation PRs instead of reading one.
//
// The PR also targets the feature branch it came from, not the repository
// default. A fix for work-in-progress belongs alongside that work, and merging
// it into main would land a change for code that has not shipped.

// branchUnsafe matches characters git refs cannot carry.
var branchUnsafe = regexp.MustCompile(`[^A-Za-z0-9._/-]+`)

// SourceBranch reports the feature branch this run is remediating.
//
// In GitHub Actions a pull-request build exposes the head branch as
// GITHUB_HEAD_REF, while a push build carries GITHUB_REF_NAME. Anything else
// must be told explicitly with --source-branch.
func SourceBranch(explicit string) string {
	for _, candidate := range []string{
		explicit,
		os.Getenv("GITHUB_HEAD_REF"), // pull_request builds
		os.Getenv("GITHUB_REF_NAME"), // push builds
	} {
		if strings.TrimSpace(candidate) != "" {
			return strings.TrimSpace(candidate)
		}
	}
	return ""
}

// autofixBranchFor names the remediation branch for a source branch.
//
// Stable by construction: the same feature branch always maps to the same
// autofix branch, so a later scan updates the existing branch and PR instead of
// opening another.
func autofixBranchFor(sourceBranch string) string {
	clean := branchUnsafe.ReplaceAllString(strings.TrimSpace(sourceBranch), "-")
	clean = strings.Trim(clean, "-/")
	if clean == "" {
		return ""
	}
	return "autofix-" + clean
}
