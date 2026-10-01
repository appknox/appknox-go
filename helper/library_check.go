package helper

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// optionalLibrary is an AndroidX/Material library a fixer reaches for that a
// project may not have: a new class extending AppCompatActivity in a Flutter
// app does not compile.
type optionalLibrary struct {
	Package  string   // import prefix, e.g. "androidx.appcompat."
	Artifact string   // what to call it in a message
	Markers  []string // build-file substrings that mean it is on the classpath
	Instead  string   // the platform alternative to suggest
}

// optionalLibraries are judged; every other import is left alone. Markers
// include the libraries that pull these in transitively (react-android,
// Capacitor and Material all depend on appcompat), because a false "missing"
// costs a correct fix.
var optionalLibraries = []optionalLibrary{
	{Package: "androidx.appcompat.", Artifact: "androidx.appcompat",
		Markers: []string{"appcompat", "com.google.android.material", "react-android", "com.facebook.react",
			"capacitor"},
		Instead: "android.app.Activity / android.app.AlertDialog"},
	{Package: "com.google.android.material.", Artifact: "com.google.android.material",
		Markers: []string{"com.google.android.material"},
		Instead: "android.widget / android.app platform classes"},
}

// importRE finds one Java/Kotlin import and its fully qualified name.
var importRE = regexp.MustCompile(`(?m)^\s*import\s+(?:static\s+)?([\w.]+)`)

// libraryDeclared reports whether any build file or version catalog mentions
// one of the markers.
func libraryDeclared(root string, markers []string) bool {
	found := false
	eachBuildFile(root, func(body string) {
		for _, m := range markers {
			if strings.Contains(body, m) {
				found = true
			}
		}
	})
	return found
}

// checkMissingLibrary rejects a Java/Kotlin patch that newly imports from an
// optional library no build file declares: the import cannot resolve.
func checkMissingLibrary(root, path, original, patched string) *patchViolation {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".java" && ext != ".kt" {
		return nil
	}
	had := map[string]bool{}
	for _, m := range importRE.FindAllStringSubmatch(original, -1) {
		had[m[1]] = true
	}
	for _, m := range importRE.FindAllStringSubmatch(patched, -1) {
		if had[m[1]] {
			continue
		}
		for _, lib := range optionalLibraries {
			if !strings.HasPrefix(m[1], lib.Package) || libraryDeclared(root, lib.Markers) {
				continue
			}
			return &patchViolation{
				Rule: "missing-library",
				Detail: fmt.Sprintf("%s imports %s, but this project does not depend on %s, so it does not "+
					"compile. Use the platform class instead (%s), or make no edit.", path, m[1], lib.Artifact,
					lib.Instead),
			}
		}
	}
	return nil
}
