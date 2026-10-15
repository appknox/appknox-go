package helper

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/appknox/appknox-go/agent"
)

// Module build scripts are editable, within limits.
//
// KnoxIQ's remediation for a whole class of findings lives in the app
// module's build script: remove a vulnerable dependency (mfva 37, jedis),
// set debuggable false for release (3), turn on minify (104). Those edits
// change settings that already exist or delete a line; they are no riskier
// than a manifest attribute. What breaks builds is the other kind of build
// edit KnoxIQ's examples also contain -- a signingConfig that reads
// KEYSTORE_PATH from an environment CI does not have (117), a Retrofit
// dependency the app never used (37's step 3), a plugin, a repository. Those
// are refused by checkBuildScriptEdit whatever the prompt said.
//
// Only a module script is in bounds: build.gradle(.kts) below the repository
// root, and not the root of a nested Gradle project (android/ in a Flutter or
// React Native repo), which editableBuildScript tells apart by its settings
// file. buildSrc is build logic, not a module. The root script, settings,
// gradle.properties, pom.xml and proguard-rules.pro stay out (buildFileRE
// still refuses them).

// moduleBuildScriptRE matches a Gradle build script by file name.
var moduleBuildScriptRE = regexp.MustCompile(`(^|/)build\.gradle(\.kts)?$`)

// isModuleBuildScript reports, from the path alone, whether rel (repo
// relative) names a module build script. editableBuildScript adds the
// on-disk check; this one is for ordering and outcome bookkeeping.
func isModuleBuildScript(rel string) bool {
	rel = filepath.ToSlash(rel)
	if !moduleBuildScriptRE.MatchString(rel) || !strings.Contains(rel, "/") {
		return false
	}
	for _, part := range strings.Split(path.Dir(rel), "/") {
		if part == "buildSrc" {
			return false
		}
	}
	return true
}

// editableBuildScript is isModuleBuildScript plus: no settings.gradle(.kts)
// next to it, which would make it the root script of a nested project.
func editableBuildScript(root, rel string) bool {
	if !isModuleBuildScript(rel) {
		return false
	}
	dir := filepath.Join(root, filepath.FromSlash(path.Dir(filepath.ToSlash(rel))))
	for _, name := range []string{"settings.gradle", "settings.gradle.kts"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return false
		}
	}
	return true
}

// dependencyConfigs are the Gradle configurations a dependency is declared
// in. Listed rather than inferred so that settings such as compileSdkVersion
// never match; \w+Implementation and friends cover per-variant forms.
const dependencyConfigs = `implementation|api|compile|compileOnly|runtimeOnly|kapt|ksp|annotationProcessor|` +
	`coreLibraryDesugaring|testCompile|androidTestCompile|wearApp|androidTestUtil|lintChecks|lintPublish|` +
	`detektPlugins|\w+Implementation|\w+Api|\w+CompileOnly|\w+RuntimeOnly|\w+AnnotationProcessor`

// dependencyLineRE matches a dependency declaration anywhere on a line,
// including one-line `dependencies { implementation 'a:b:1' }`, the Kotlin
// DSL's add("implementation", ...) and "implementation"(...). A configuration
// name followed by `{` is a configuration block (kapt { ... }), not a
// declaration, and does not match.
var dependencyLineRE = regexp.MustCompile(
	`\b(` + dependencyConfigs + `)\s*(\(|['"]|\s+[\w'"])` +
		`|\badd\s*\(\s*["']\w+["']` +
		`|["'](` + dependencyConfigs + `)["']\s*\(`)

// dependencyCoordRE pulls group and artifact out of a 'group:artifact[:version]'
// notation.
var dependencyCoordRE = regexp.MustCompile(`['"]([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+)(:[^'"]*)?['"]`)

// dependencyMapRE pulls group and name out of the map notation
// group: 'x', name: 'y'.
var (
	dependencyMapGroupRE = regexp.MustCompile(`\bgroup\s*[:=]\s*['"]([^'"]+)['"]`)
	dependencyMapNameRE  = regexp.MustCompile(`\bname\s*[:=]\s*['"]([^'"]+)['"]`)
)

// buildScriptForbidden lists what a patch to a build script may not ADD, each
// with the fact handed back to the fixer on retry. Matched per added,
// non-comment line.
var buildScriptForbidden = []struct {
	re     *regexp.Regexp
	detail string
}{
	{dependencyLineRE, "adds a dependency. A fix may remove a dependency the remediation names, never add one"},
	{regexp.MustCompile(`\bsigningConfigs?\b`),
		"adds signing configuration, which needs keys and secrets this repository does not hold"},
	{regexp.MustCompile(`System\.getenv|environmentVariable\s*\(|System\.getProperty|findProperty\s*\(`),
		"reads an environment variable or property that CI is not known to set"},
	{regexp.MustCompile(`\bapply\s+plugin\b|^\s*id[\s(]|\bplugins\s*\{|\bclasspath\b`), "adds a Gradle plugin"},
	{regexp.MustCompile(`\bmaven\s*[\{(]|mavenCentral\s*\(|jcenter\s*\(|google\s*\(\s*\)|\brepositories\s*\{`),
		"adds a dependency repository"},
}

// checkBuildScriptEdit refuses a module build-script patch that adds anything
// buildScriptForbidden lists. Only lines the patch introduced are judged, so a
// script that already declares signing or plugins is not blamed for them.
func checkBuildScriptEdit(p, original, patched string) *patchViolation {
	if !isModuleBuildScript(p) {
		return nil
	}
	// The blocklist reads code lines (comments stripped) for its specific
	// messages; the allowlist reads the RAW added lines, because stripping
	// comments without knowing strings is exactly what let code hide.
	lines := append(addedCodeLines(original, patched), rawAddedLines(original, patched)...)
	for _, line := range lines {
		detail := ""
		for _, f := range buildScriptForbidden {
			if f.re.MatchString(line) {
				detail = f.detail
				break
			}
		}
		if detail == "" && !allowedBuildLine(line) {
			detail = "adds something other than a release setting (debuggable, minifyEnabled, " +
				"shrinkResources, proguardFiles, min/target/compileSdkVersion) inside android { }"
		}
		if detail != "" {
			return &patchViolation{
				Rule: "build-script-addition",
				Detail: fmt.Sprintf("your edit to %s %s: %q. Change or remove only what the "+
					"remediation names; if it needs this, make no edit and report it.",
					p, detail, strings.TrimSpace(line)),
			}
		}
	}
	// Moving a } re-nests a block without adding or removing a line: the
	// release setting lands in debug { } and the finding looks fixed. Every
	// line kept by the patch must stay in the block it was in.
	if line := movedBetweenBlocks(original, patched); line != "" {
		return &patchViolation{
			Rule: "build-script-renest",
			Detail: fmt.Sprintf("your edit to %s moves %q into a different block. Change settings "+
				"where they are; never move a brace.", p, line),
		}
	}
	// Deleting can switch code on too: drop a block comment's /* and */ and
	// whatever it held runs. So a removed line must be one an edit may add, a
	// dependency line (checkRemovedDependency judges those), or a // comment.
	for _, line := range rawAddedLines(patched, original) {
		if !allowedBuildRemoval(line) {
			return &patchViolation{
				Rule: "build-script-removal",
				Detail: fmt.Sprintf("your edit to %s removes %q, which is neither a setting nor a "+
					"dependency line. Remove only what the remediation names; never a comment "+
					"marker or a task.", p, strings.TrimSpace(line)),
			}
		}
	}
	return nil
}

// movedBetweenBlocks returns a line whose enclosing block path differs
// between original and patched, for lines appearing equally often in both.
func movedBetweenBlocks(original, patched string) string {
	before, after := blockPaths(original), blockPaths(patched)
	for line, paths := range before {
		now, ok := after[line]
		if !ok || len(now) != len(paths) {
			continue // added or removed: judged by the allow lists
		}
		for i := range paths {
			if paths[i] != now[i] {
				return line
			}
		}
	}
	return ""
}

// blockPaths maps each trimmed non-blank line to the block path (enclosing
// block names, outermost first) of each of its occurrences, in order.
func blockPaths(src string) map[string][]string {
	out := map[string][]string{}
	var stack []string
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		out[line] = append(out[line], strings.Join(stack, "/"))
		seg := 0
		for i, r := range line {
			switch r {
			case '{':
				stack = append(stack, strings.TrimSpace(line[seg:i]))
				seg = i + 1
			case '}':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				seg = i + 1
			case ';':
				seg = i + 1
			}
		}
	}
	return out
}

// allowedBuildRemoval reports whether a build-script line may be deleted.
func allowedBuildRemoval(line string) bool {
	if strings.Contains(line, "/*") || strings.Contains(line, "*/") {
		return false
	}
	t := strings.TrimSpace(line)
	// A dependency line must be only that: no braces or ; joining it to code
	// (an `if (false) {` riding on it would switch a block on when removed).
	plainDependency := dependencyLineRE.MatchString(t) && !strings.ContainsAny(t, "{};")
	return strings.HasPrefix(t, "//") || plainDependency || allowedBuildLine(t)
}

// Added build-script lines are held to an allowlist, not only the blocklist
// above: a Gradle script is a program, and apply from:, "cmd".execute() or an
// exec { } task run at the next sync on whoever builds the app. What KnoxIQ's
// build remediations actually add is a handful of settings inside the android
// block's defaultConfig or build types, so each added line must split (on
// braces and semicolons, after a trailing // comment) into nothing but those
// settings and the block names that hold them.
var (
	buildBlockRE = regexp.MustCompile(
		`^(android|defaultConfig|buildTypes|release|debug|(getByName|named|create)\(\s*"\w+"\s*\))$`)
	buildFlagRE = regexp.MustCompile(
		`^(debuggable|minifyEnabled|shrinkResources|jniDebuggable|renderscriptDebuggable|` +
			`isDebuggable|isMinifyEnabled|isShrinkResources|isJniDebuggable|isRenderscriptDebuggable)` +
			`(\s+|\s*=\s*)(true|false)$`)
	buildSdkRE = regexp.MustCompile(
		`^(minSdkVersion|targetSdkVersion|compileSdkVersion|minSdk|targetSdk|compileSdk)` +
			`(\s+\d+|\s*=\s*\d+|\s*\(\s*\d+\s*\))$`)
	proguardArg  = `(getDefaultProguardFile\(\s*['"][\w.-]+['"]\s*\)|['"][\w.-]+['"])`
	proguardArgs = proguardArg + `(\s*,\s*` + proguardArg + `)*`
	// Parentheses must close on the same line: an open one lets the next line
	// continue the expression.
	proguardRE = regexp.MustCompile(`^(proguardFiles?|setProguardFiles)(\s+` + proguardArgs +
		`|\s*\(\s*` + proguardArgs + `\s*\)|\s*\(\s*listOf\(\s*` + proguardArgs + `\s*\)\s*\))$`)
	buildSplitRE = regexp.MustCompile(`[{};]`)
	// buildUnsafeRE marks what cannot be judged one line at a time: block
	// comments (they span lines and hide what follows), a line continuing one,
	// GString interpolation, and escapes.
	buildUnsafeRE = regexp.MustCompile("/\\*|\\*/|^\\s*\\*|[$`\\\\]")
)

// allowedBuildLine reports whether every piece of an added line is an
// allowlisted block name or setting.
func allowedBuildLine(line string) bool {
	if buildUnsafeRE.MatchString(line) {
		return false
	}
	if i := strings.Index(line, "//"); i >= 0 {
		line = line[:i]
	}
	for _, part := range buildSplitRE.Split(line, -1) {
		part = strings.TrimSpace(part)
		if part == "" || buildBlockRE.MatchString(part) || buildFlagRE.MatchString(part) ||
			buildSdkRE.MatchString(part) || proguardRE.MatchString(part) {
			continue
		}
		return false
	}
	return true
}

// checkRemovedDependency refuses a build-script patch that drops a dependency
// the app's own source may still use.
//
// It runs against the tree on disk, where the remediation's source targets
// have already been fixed (targetRank puts build scripts last). So for jedis:
// ExportedActivity.java's import is gone first, and only then can
// redis.clients:jedis leave app/build.gradle. If the source fix did not land,
// removing the dependency would break compilation, and this is what stops it.
//
// Every removed declaration must resolve to a group; one that does not -- a
// version-catalog alias (libs.jedis), project(':x'), a fileTree -- is refused,
// since nothing here can tell which package it provides. The group is taken
// as the package prefix. That holds for most libraries (redis.clients,
// org.apache.commons) but not all (com.squareup.okhttp3 ships package
// okhttp3); where it does not, nothing matches and the check passes -- the
// unit-level all-or-nothing rule in fixTargets is the backstop for those.
func checkRemovedDependency(root, p, original, patched string) *patchViolation {
	if !isModuleBuildScript(p) {
		return nil
	}
	for _, line := range removedDependencyLines(original, patched) {
		group := dependencyGroup(line)
		if group == "" {
			return &patchViolation{
				Rule: "dependency-unresolved",
				Detail: fmt.Sprintf("your edit removes %q from %s, and its package cannot be "+
					"read off the line, so there is no way to check that no source still uses it. "+
					"Leave it in place and report it.", strings.TrimSpace(line), p),
			}
		}
		if !strings.Contains(group, ".") {
			continue // no dot: cannot be a package prefix, nothing to search for
		}
		if user := firstSourceReferencing(root, group); user != "" {
			return &patchViolation{
				Rule: "dependency-still-used",
				Detail: fmt.Sprintf("your edit removes the %s dependency from %s, but %s still "+
					"references %s. Leave the dependency in place; it can go only once no "+
					"source uses it.", group, p, user, group),
			}
		}
	}
	return nil
}

// removedDependencyLines returns the dependency declarations of original that
// patched no longer has (deleted, commented out, or rewritten), compared line
// by line so a sibling artifact of the same group cannot hide a removal.
func removedDependencyLines(original, patched string) []string {
	var out []string
	for _, line := range addedCodeLines(patched, original) {
		if dependencyLineRE.MatchString(line) {
			out = append(out, line)
		}
	}
	return out
}

// dependencyGroup returns the group a dependency declaration line names, or ""
// when it cannot be read off the line.
func dependencyGroup(line string) string {
	if m := dependencyCoordRE.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if m := dependencyMapGroupRE.FindStringSubmatch(line); m != nil && dependencyMapNameRE.MatchString(line) {
		return m[1]
	}
	return ""
}

// firstSourceReferencing returns the first first-party Java/Kotlin file (repo
// relative) whose code names pkg as a package, or "" when none does. The walk
// skips the same directories the locate tools skip (build output, vendored
// code, hidden and nested repositories) and never follows a symlink.
func firstSourceReferencing(root, pkg string) string {
	needle := regexp.MustCompile(`(^|[^\w.])` + regexp.QuoteMeta(pkg) + `\.`)
	found := ""
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && agent.PruneDir(root, p) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		switch strings.ToLower(path.Ext(p)) {
		case ".java", ".kt":
		default:
			return nil
		}
		body, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		if needle.MatchString(stripLiteralsAndComments(string(body))) {
			rel, _ := filepath.Rel(root, p)
			found = filepath.ToSlash(rel)
			return filepath.SkipAll
		}
		return nil
	})
	if walkErr != nil && found == "" {
		// An unreadable tree cannot prove the dependency unused; refuse the
		// removal rather than let it through on no evidence.
		return "(repository walk failed: " + walkErr.Error() + ")"
	}
	return found
}

// inlineBlockCommentRE matches a /* ... */ comment closed on the same line.
var inlineBlockCommentRE = regexp.MustCompile(`/\*.*?\*/`)

// codeLines returns the lines of src that are not blank and not comments.
// A block comment closed on its own line is cut out first, so
// "/* x */ implementation 'a:b:1'" still reads as the declaration it is.
func codeLines(src string) []string {
	var out []string
	for _, line := range strings.Split(src, "\n") {
		line = inlineBlockCommentRE.ReplaceAllString(line, "")
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// rawAddedLines returns the non-blank lines of patched that original does not
// have, comments and all, counted as a multiset.
func rawAddedLines(original, patched string) []string {
	have := map[string]int{}
	for _, line := range strings.Split(original, "\n") {
		have[strings.TrimSpace(line)]++
	}
	var out []string
	for _, line := range strings.Split(patched, "\n") {
		k := strings.TrimSpace(line)
		if k == "" {
			continue
		}
		if have[k] > 0 {
			have[k]--
			continue
		}
		out = append(out, line)
	}
	return out
}

// addedCodeLines returns the code lines of patched that original does not
// have, counted as a multiset so a duplicated line still counts as added.
func addedCodeLines(original, patched string) []string {
	have := map[string]int{}
	for _, line := range codeLines(original) {
		have[strings.TrimSpace(line)]++
	}
	var out []string
	for _, line := range codeLines(patched) {
		k := strings.TrimSpace(line)
		if have[k] > 0 {
			have[k]--
			continue
		}
		out = append(out, line)
	}
	return out
}
