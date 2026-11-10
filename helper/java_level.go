package helper

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// The Java language level a project compiles at.
//
// mfva's verify build (run 36089101135) failed on the fixer's
// `new Thread(() -> {...})`: "lambda expressions are not supported in
// -source 1.7". Nothing in the patch was wrong for Java 8; the project is not
// Java 8. The level is read, not guessed: an explicit sourceCompatibility or
// toolchain wins, otherwise the Android Gradle Plugin's default applies --
// Java 8 from AGP 4.2, Java 7 before it. When neither is readable the gate
// abstains.

// explicitJavaLevelREs read a declared language level. Each first group is the
// major version (VERSION_1_8 and '1.8' both give 8).
var explicitJavaLevelREs = []*regexp.Regexp{
	regexp.MustCompile(`sourceCompatibility\s*=?\s*JavaVersion\.VERSION_(?:1_)?(\d+)`),
	regexp.MustCompile(`sourceCompatibility\s*=?\s*['"](?:1\.)?(\d+)`),
	regexp.MustCompile(`jvmToolchain\s*\(\s*(\d+)\s*\)`),
	regexp.MustCompile(`JavaLanguageVersion\.of\s*\(\s*(\d+)\s*\)`),
}

// agpVersionFullREs read the Android Gradle Plugin's major and minor version,
// in the same three spellings agpVersionREs accepts.
var agpVersionFullREs = []*regexp.Regexp{
	regexp.MustCompile(`com\.android\.tools\.build:gradle:(\d+)\.(\d+)`),
	regexp.MustCompile(`agp\s*=\s*["'](\d+)\.(\d+)`),
	regexp.MustCompile(`com\.android\.application.{0,4}\s+version\s+["'](\d+)\.(\d+)`),
}

// java8SyntaxRE matches the Java 8 syntax a fixer reaches for: a lambda arrow
// or a method reference. Run over code with literals and comments stripped.
var java8SyntaxRE = regexp.MustCompile(`->|::`)

// javaLanguageLevel returns the project's Java language level, or 0 if it
// cannot be read. Of several explicit declarations the lowest wins: a patch
// may land in any module, and the strictest one decides whether it compiles.
func javaLanguageLevel(root string) int {
	lowest := 0
	eachBuildFile(root, func(body string) {
		for _, re := range explicitJavaLevelREs {
			for _, m := range re.FindAllStringSubmatch(body, -1) {
				if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && (lowest == 0 || n < lowest) {
					lowest = n
				}
			}
		}
	})
	if lowest > 0 {
		return lowest
	}
	major, minor := agpVersion(root)
	switch {
	case major == 0:
		return 0
	case major > 4 || (major == 4 && minor >= 2):
		return 8
	default:
		return 7
	}
}

// agpVersion returns the highest Android Gradle Plugin major.minor any build
// file names, or 0, 0.
func agpVersion(root string) (int, int) {
	bestMajor, bestMinor := 0, 0
	eachBuildFile(root, func(body string) {
		for _, re := range agpVersionFullREs {
			for _, m := range re.FindAllStringSubmatch(body, -1) {
				major, errMajor := strconv.Atoi(m[1])
				minor, errMinor := strconv.Atoi(m[2])
				if errMajor != nil || errMinor != nil {
					continue
				}
				if major > bestMajor || (major == bestMajor && minor > bestMinor) {
					bestMajor, bestMinor = major, minor
				}
			}
		}
	})
	return bestMajor, bestMinor
}

// checkJavaLanguageLevel refuses a Java patch that introduces a lambda or a
// method reference into a project compiling below Java 8. Only syntax the
// patch added is judged, and the build files are read only when it added some.
func checkJavaLanguageLevel(root, path, original, patched string) *patchViolation {
	if !strings.EqualFold(filepath.Ext(path), ".java") {
		return nil
	}
	before := len(java8SyntaxRE.FindAllString(stripLiteralsAndComments(original), -1))
	after := len(java8SyntaxRE.FindAllString(stripLiteralsAndComments(patched), -1))
	if after <= before {
		return nil
	}
	level := javaLanguageLevel(root)
	if level == 0 || level >= 8 {
		return nil
	}
	return &patchViolation{
		Rule: "java-language-level",
		Detail: fmt.Sprintf("this project compiles as Java %d, and your edit to %s adds a lambda (->) "+
			"or a method reference (::), which need Java 8. Write an anonymous class instead "+
			"(new Runnable() { @Override public void run() { ... } }).", level, path),
	}
}
