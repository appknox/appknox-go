package helper

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Static checks run against a produced patch BEFORE it is applied.
//
// Every check corresponds to a build break observed on 2026-09-09, when 8 of 20
// autofix branches failed to compile. They are facts about the repository on
// disk, not judgements: two repos received the same remediation and the same
// prompt rule and diverged -- kgb_messenger avoided a dangling resource
// reference, playstore-auth wrote one anyway. A filesystem check cannot diverge.
//
// Deliberately NOT a compiler. Running Gradle here would cost minutes per file
// and duplicate the branch build that already happens downstream.
//
// TWO RULES, both learned by getting them wrong on the corpus run of
// 2026-09-11, where an earlier version of this file rejected 75 patches and
// dropped 36 -- roughly half of them good:
//
//  1. CHECK ONLY WHAT THE PATCH ADDED. Fossify Calendar lost all 10 of its
//     fixes because its manifest already referenced @drawable/img_widget_date_-
//     preview, a line the fixer never touched. Judging the whole file blames
//     the fixer for the repository it was handed.
//
//  2. CHECK ONLY WHAT THE FILESYSTEM CAN DECIDE. The same run rejected
//     timber.log.Timber and org.apache.http.HttpResponse as "unresolved"
//     because no source file declares them -- they come from the Gradle
//     dependency graph, which is not on disk and is not readable from here.
//     That check is gone. A check that cannot be sure belongs in the build, not
//     in a gate that silently discards fixes.

// buildFileRE matches files that configure the build rather than the app.
//
// SCOPE has placed these out of bounds since before the corpus run;
// aibom-android edited app/build.gradle.kts anyway, twice, under two separate
// rules forbidding it. A path check does not rely on compliance.
var buildFileRE = regexp.MustCompile(
	`(^|/)(build\.gradle(\.kts)?|settings\.gradle(\.kts)?|gradle\.properties|pom\.xml|proguard-rules\.pro)$`)

// resourceRefRE finds Android resource references, e.g.
// android:networkSecurityConfig="@xml/network_security_config".
var resourceRefRE = regexp.MustCompile(`@(xml|drawable|layout|raw|menu|anim)/([A-Za-z0-9_]+)`)

// buildConfigImportRE matches an import of BuildConfig, the one generated
// symbol whose absence is both common and fatal: it exists only if the build
// generates it for that exact package, and allsafe-android broke importing one
// its package does not have.
//
// R is deliberately NOT matched. It is generated for every Android module with
// resources, so rejecting it cost Anki-Android a valid fix on the 2026-09-11
// run for no corresponding break.
var buildConfigImportRE = regexp.MustCompile(`(?m)^\s*import\s+([\w.]+\.BuildConfig)\b`)

// mergedAttrRE matches manifest attributes AGP merges across source sets, which
// therefore conflict when one manifest of a set is changed alone.
//
// The value is part of the match so that "the patch set this attribute" can be
// told from "the attribute was already there" -- see introduced().
var mergedAttrRE = regexp.MustCompile(
	`android:(allowBackup|debuggable|usesCleartextTraffic|networkSecurityConfig|launchMode|taskAffinity)\s*=\s*"[^"]*"`)

// patchViolation is a reason a patch must not be applied, phrased for the fixer.
type patchViolation struct {
	Rule   string // short name, for the run report
	Detail string // the specific fact, handed back on retry
}

func (v patchViolation) Error() string { return v.Rule + ": " + v.Detail }

// verifyPatch reports the first reason the patch cannot be applied, or nil.
//
// Cheapest check first, and stops at the first violation: the fixer gets one
// retry, so one precise fact beats a list it has to triage.
func verifyPatch(root, path, original, patched string) *patchViolation {
	if v := checkEditablePath(path); v != nil {
		return v
	}
	// Whole-file, and the one check that must be: a document either parses or
	// it does not, and an edit can break it from any line.
	if v := checkXMLWellFormed(path, patched); v != nil {
		return v
	}
	if v := checkResourceRefs(root, path, original, patched); v != nil {
		return v
	}
	if v := checkBuildConfigImport(original, patched); v != nil {
		return v
	}
	return checkSiblingManifests(root, path, original, patched)
}

// introduced returns the matches of re in patched whose whole matched text does
// not already appear in the original.
//
// Token-level rather than line-level, because a line-level delta still blames
// the fixer for its own file: adding android:allowBackup to a line that already
// carried android:banner="@drawable/x" marks that whole line new, and the
// drawable with it. Comparing the matched text itself cannot make that mistake.
func introduced(re *regexp.Regexp, original, patched string) [][]string {
	var out [][]string
	for _, m := range re.FindAllStringSubmatch(patched, -1) {
		if strings.Contains(original, m[0]) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// checkEditablePath rejects build scripts, which SCOPE places out of bounds.
func checkEditablePath(path string) *patchViolation {
	if !buildFileRE.MatchString(filepath.ToSlash(path)) {
		return nil
	}
	return &patchViolation{
		Rule: "build-file",
		Detail: fmt.Sprintf("%s configures the build, not the app. Build-script changes "+
			"are out of scope: make no edit and report the step instead.", path),
	}
}

// checkXMLWellFormed parses the patched content when the target is XML.
//
// AndroGoat's manifest ended up with </manifest> written mid-element, leaving a
// document the merger could not parse. The fixer edits XML as text and has no
// parser; this is that parser.
func checkXMLWellFormed(path, content string) *patchViolation {
	if !strings.EqualFold(filepath.Ext(path), ".xml") {
		return nil
	}
	dec := xml.NewDecoder(strings.NewReader(content))
	for {
		_, err := dec.Token()
		if err == nil {
			continue
		}
		if err.Error() == "EOF" {
			return nil
		}
		return &patchViolation{
			Rule: "malformed-xml",
			Detail: fmt.Sprintf("your edit leaves %s unparseable: %v. Every tag must be "+
				"closed once, in order, with a single root element.", path, err),
		}
	}
}

// checkResourceRefs rejects a NEWLY ADDED reference to a resource not on disk.
//
// The fixer cannot create files, so a remediation whose first step is "create
// res/xml/network_security_config.xml" leaves it able to perform only the
// second -- pointing the manifest at a file never written. That is an AAPT
// error, and it broke kgb_messenger and playstore-auth identically.
func checkResourceRefs(root, path, original, patched string) *patchViolation {
	for _, m := range introduced(resourceRefRE, original, patched) {
		kind, name := m[1], m[2]
		if resourceExists(root, kind, name) {
			continue
		}
		return &patchViolation{
			Rule: "missing-resource",
			Detail: fmt.Sprintf("%s adds a reference to @%s/%s, but no res/%s/%s.* exists "+
				"in this repository and you cannot create files. Achieve the fix without "+
				"it (a manifest attribute often has an equivalent), or make no edit.",
				path, kind, name, kind, name),
		}
	}
	return nil
}

// resourceDirRE matches a resource directory of the given kind, INCLUDING its
// qualified variants -- res/drawable-nodpi, res/values-night, res/layout-land.
//
// Matching only the bare directory is what cost Fossify Calendar every one of
// its fixes: the drawable it referenced was real, and sitting in drawable-nodpi.
func resourceDirRE(kind string) *regexp.Regexp {
	return regexp.MustCompile(`(^|/)res/` + regexp.QuoteMeta(kind) + `(-[^/]+)?/`)
}

// resourceExists looks for res/<kind>[-qualifier]/<name>.* anywhere in the
// checkout, so flavour and library source sets count, not only the main one.
func resourceExists(root, kind, name string) bool {
	dir := resourceDirRE(kind)
	found := false
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || found {
			return nil
		}
		slash := filepath.ToSlash(p)
		if !dir.MatchString(slash) {
			return nil
		}
		base := filepath.Base(slash)
		if strings.TrimSuffix(base, filepath.Ext(base)) == name {
			found = true
		}
		return nil
	})
	return found
}

// checkBuildConfigImport rejects a newly added BuildConfig import.
//
// BuildConfig is generated per module, for the module's own package. An import
// naming any other package compiles only by luck, and allsafe-android was not
// lucky. This is the only import this file judges: everything else may come
// from the Gradle dependency graph, which is not on disk.
func checkBuildConfigImport(original, patched string) *patchViolation {
	added := introduced(buildConfigImportRE, original, patched)
	if len(added) == 0 {
		return nil
	}
	return &patchViolation{
		Rule: "generated-symbol",
		Detail: fmt.Sprintf("%s is generated by the build and exists only for the module "+
			"that declares that package. Do not import it; achieve the fix without it, "+
			"or make no edit.", added[0][1]),
	}
}

// checkSiblingManifests rejects a manifest attribute the patch CHANGED when
// another manifest in the project sets the same attribute.
//
// Anki-Android set allowBackup="false" in the main manifest while the amazon and
// benchmark flavour manifests declared the opposite, and the merger failed. The
// fixer sees one file and cannot know the others exist; this tells it.
func checkSiblingManifests(root, path, original, patched string) *patchViolation {
	if filepath.Base(path) != "AndroidManifest.xml" {
		return nil
	}
	// Matched with its value, so an attribute the patch left alone is not
	// counted as set by the patch.
	attrs := map[string]bool{}
	for _, m := range introduced(mergedAttrRE, original, patched) {
		attrs[m[1]] = true
	}
	if len(attrs) == 0 {
		return nil
	}
	conflict, other := findManifestConflict(root, path, attrs)
	if conflict == "" {
		return nil
	}
	rel := strings.TrimPrefix(other, root+string(filepath.Separator))
	return &patchViolation{
		Rule: "manifest-merge-conflict",
		Detail: fmt.Sprintf("android:%s is also set in %s. Changing it in only one manifest "+
			"of a merged set fails the manifest merger. Leave it and report the conflict.",
			conflict, filepath.ToSlash(rel)),
	}
}

// findManifestConflict returns the first attribute another manifest also sets,
// and the manifest that sets it.
func findManifestConflict(root, path string, attrs map[string]bool) (string, string) {
	var conflict, other string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || conflict != "" {
			return nil
		}
		if filepath.Base(p) != "AndroidManifest.xml" || sameFile(p, root, path) {
			return nil
		}
		b, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil
		}
		for _, m := range mergedAttrRE.FindAllStringSubmatch(string(b), -1) {
			if attrs[m[1]] {
				conflict, other = m[1], p
				return nil
			}
		}
		return nil
	})
	return conflict, other
}

// sameFile reports whether an absolute walk path is the repo-relative target.
func sameFile(abs, root, rel string) bool {
	return filepath.ToSlash(abs) == filepath.ToSlash(filepath.Join(root, rel))
}
