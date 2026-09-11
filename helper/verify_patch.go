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
// Deliberately NOT a compiler. Running Gradle here would cost 2-15 minutes per
// run and duplicate the branch build that already happens downstream. These cost
// milliseconds and catch 6 of the 8 observed breaks; the one that slips through
// (an unreported checked exception) is left to that build.
//
// A violation is reported to the fixer once, with the specific fact it got
// wrong, and the patch is retried a single time.

// buildFileRE matches files that configure the build rather than the app.
//
// SCOPE has placed these out of bounds since before the corpus run;
// aibom-android edited app/build.gradle.kts anyway, twice, under two separate
// rules forbidding it. A path check does not rely on compliance.
var buildFileRE = regexp.MustCompile(
	`(^|/)(build\.gradle(\.kts)?|settings\.gradle(\.kts)?|gradle\.properties|pom\.xml|proguard-rules\.pro)$`)

// resourceRefRE finds Android resource references, e.g.
// android:networkSecurityConfig="@xml/network_security_config".
var resourceRefRE = regexp.MustCompile(`@(xml|drawable|layout|raw|values|menu|anim)/([A-Za-z0-9_]+)`)

// importRE finds Java/Kotlin import statements.
var importRE = regexp.MustCompile(`(?m)^\s*import\s+([A-Za-z_][\w.]*)`)

// platformPrefixes are packages supplied by the platform or a dependency rather
// than this repository's sources, so their absence from the checkout proves
// nothing.
var platformPrefixes = []string{
	"android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.",
	"com.google.", "org.json.", "org.w3c.", "org.xml.", "dalvik.", "okhttp3.",
	"retrofit2.", "com.squareup.", "org.jetbrains.",
}

// generatedSymbols are produced by the build, not present as source. Naming one
// costs a compile when it is not generated for that module -- allsafe-android
// broke importing a BuildConfig its package does not have.
var generatedSymbols = []string{"BuildConfig", "R", "DataBinderMapperImpl", "Manifest"}

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
func verifyPatch(root, path, content string) *patchViolation {
	if v := checkEditablePath(path); v != nil {
		return v
	}
	if v := checkXMLWellFormed(path, content); v != nil {
		return v
	}
	if v := checkResourceRefs(root, path, content); v != nil {
		return v
	}
	if v := checkImports(root, content); v != nil {
		return v
	}
	return checkSiblingManifests(root, path, content)
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

// checkResourceRefs rejects a reference to an Android resource not on disk.
//
// The fixer cannot create files, so a remediation whose first step is "create
// res/xml/network_security_config.xml" leaves it able to perform only the
// second -- pointing the manifest at a file never written. That is an AAPT
// error, and it broke kgb_messenger and playstore-auth identically.
func checkResourceRefs(root, path, content string) *patchViolation {
	for _, m := range resourceRefRE.FindAllStringSubmatch(content, -1) {
		kind, name := m[1], m[2]
		if resourceExists(root, kind, name) {
			continue
		}
		return &patchViolation{
			Rule: "missing-resource",
			Detail: fmt.Sprintf("%s references @%s/%s, but no res/%s/%s.* exists in this "+
				"repository and you cannot create files. Achieve the fix without it (a "+
				"manifest attribute often has an equivalent), or make no edit.",
				path, kind, name, kind, name),
		}
	}
	return nil
}

// resourceExists looks for res/<kind>/<name>.* anywhere in the checkout, so
// flavour and library source sets count, not only the main one.
func resourceExists(root, kind, name string) bool {
	found := false
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || found {
			return nil
		}
		slash := filepath.ToSlash(p)
		if !strings.Contains(slash, "/res/"+kind+"/") {
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

// checkImports rejects an import resolving to neither a platform package nor a
// source file in this repository.
//
// A generated symbol counts as unresolved: BuildConfig exists only if the build
// generates it for that package.
func checkImports(root, content string) *patchViolation {
	for _, m := range importRE.FindAllStringSubmatch(content, -1) {
		imp := strings.TrimSuffix(m[1], ";")
		if hasAnyPrefix(imp, platformPrefixes) {
			continue
		}
		parts := strings.Split(imp, ".")
		leaf := parts[len(parts)-1]
		if containsString(generatedSymbols, leaf) {
			return &patchViolation{
				Rule: "generated-symbol",
				Detail: fmt.Sprintf("%s is generated by the build and may not exist for this "+
					"module. Do not import it; achieve the fix without it, or make no edit.", imp),
			}
		}
		if sourceFileExists(root, leaf) {
			continue
		}
		return &patchViolation{
			Rule: "unresolved-import",
			Detail: fmt.Sprintf("%s does not resolve to any source file in this repository. "+
				"Do not name a type you have not read.", imp),
		}
	}
	return nil
}

// sourceFileExists reports whether a .java or .kt file named for that type
// exists anywhere in the checkout.
//
// Matched on file name rather than package path: Kotlin allows several types per
// file, so this errs towards accepting. It exists to catch a name that appears
// nowhere at all, not to police package structure.
func sourceFileExists(root, typeName string) bool {
	found := false
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || found {
			return nil
		}
		base := filepath.Base(p)
		if base == typeName+".java" || base == typeName+".kt" {
			found = true
		}
		return nil
	})
	return found
}

// mergedAttrRE matches manifest attributes AGP merges across source sets, which
// therefore conflict when one manifest of a set is changed alone.
var mergedAttrRE = regexp.MustCompile(
	`android:(allowBackup|debuggable|usesCleartextTraffic|networkSecurityConfig|launchMode|taskAffinity)\s*=`)

// checkSiblingManifests rejects a manifest attribute change when another
// manifest in the project sets the same attribute.
//
// Anki-Android set allowBackup="false" in the main manifest while the amazon and
// benchmark flavour manifests declared the opposite, and the merger failed. The
// fixer sees one file and cannot know the others exist; this tells it.
func checkSiblingManifests(root, path, content string) *patchViolation {
	if filepath.Base(path) != "AndroidManifest.xml" {
		return nil
	}
	attrs := map[string]bool{}
	for _, m := range mergedAttrRE.FindAllStringSubmatch(content, -1) {
		attrs[m[1]] = true
	}
	if len(attrs) == 0 {
		return nil
	}
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

// sameFile reports whether an absolute walk path is the repo-relative target.
func sameFile(abs, root, rel string) bool {
	return filepath.ToSlash(abs) == filepath.ToSlash(filepath.Join(root, rel))
}

// containsString is spelled out rather than named contains: the package's test
// helper already owns that name with a substring meaning.
func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
