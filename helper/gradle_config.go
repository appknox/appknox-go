package helper

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// Facts read out of Gradle build files.
//
// SCOPE forbids EDITING a build script -- checkEditablePath rejects any patch
// that touches one. READING one is a different matter, and necessary: the build
// files are the only place on disk that say which API level a module compiles
// against and which generated symbols the build will actually emit. Without
// them the gate would have to guess, and this gate does not guess.

// compileSdkRE reads the API level a module compiles against, in any of the
// spellings Gradle accepts: compileSdkVersion 34, compileSdk 34, compileSdk = 34.
var compileSdkRE = regexp.MustCompile(`compileSdk(?:Version)?\s*=?\s*(\d+)`)

// buildConfigEnabledRE matches buildFeatures { buildConfig true } and its
// Kotlin-DSL form, buildConfig = true.
var buildConfigEnabledRE = regexp.MustCompile(`buildConfig\s*=?\s*true`)

// agpVersionREs read the Android Gradle Plugin major version. Three spellings
// are in use across the corpus and all three appear in real projects.
var agpVersionREs = []*regexp.Regexp{
	regexp.MustCompile(`com\.android\.tools\.build:gradle:(\d+)\.`),               // classpath
	regexp.MustCompile(`agp\s*=\s*["'](\d+)\.`),                                   // version catalog
	regexp.MustCompile(`com\.android\.application.{0,4}\s+version\s+["'](\d+)\.`), // plugins DSL
}

// eachBuildFile hands fn the contents of every Gradle build file under root,
// plus the version catalog, which is where many projects now name the AGP.
func eachBuildFile(root string, fn func(body string)) {
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		switch filepath.Base(p) {
		case "build.gradle", "build.gradle.kts", "libs.versions.toml":
		default:
			return nil
		}
		if b, readErr := os.ReadFile(p); readErr == nil {
			fn(string(b))
		}
		return nil
	})
}

// repoCompileSdk returns the highest compileSdk any build file declares, or 0.
//
// The highest rather than the edited module's own: a patch is judged against
// what the project as a whole may legally reference, and reading the wrong
// module's value would be worse than reading the most permissive one.
func repoCompileSdk(root string) int {
	return highestMatch(root, compileSdkRE)
}

// agpMajor returns the Android Gradle Plugin major version, or 0 if unreadable.
func agpMajor(root string) int {
	best := 0
	for _, re := range agpVersionREs {
		if n := highestMatch(root, re); n > best {
			best = n
		}
	}
	return best
}

// highestMatch returns the largest integer the expression's first group matches
// across every build file, or 0.
func highestMatch(root string, re *regexp.Regexp) int {
	best := 0
	eachBuildFile(root, func(body string) {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if n, err := strconv.Atoi(m[1]); err == nil && n > best {
				best = n
			}
		}
	})
	return best
}

// buildConfigEnabled reports whether any module turns BuildConfig generation on.
func buildConfigEnabled(root string) bool {
	found := false
	eachBuildFile(root, func(body string) {
		if buildConfigEnabledRE.MatchString(body) {
			found = true
		}
	})
	return found
}
