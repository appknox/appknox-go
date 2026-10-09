package helper

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/appknox/appknox-go/workspace"
)

// Which Android library family a project builds against: the Support Library
// (android.support.*) or AndroidX (androidx.*). They never coexist on one
// classpath, and the same class lives in both, so a fixer that guesses gets a
// file that does not compile and takes every class that uses it down too.
//
// mfva PR #42, 2026-10-09: a new SecureBaseActivity imported
// androidx.appcompat.app.AppCompatActivity in a project on
// com.android.support:appcompat-v7, and the five activities moved onto it lost
// findViewById, setContentView and every other inherited method -- 46 errors
// from one import.
//
// A verdict is given only when the files on disk agree; anything mixed or
// silent is libUnknown and judged by nobody (CHECK ONLY WHAT THE FILESYSTEM
// CAN DECIDE, verify_patch.go).

type androidLibrary int

const (
	libUnknown androidLibrary = iota
	libSupport
	libAndroidX
)

var (
	useAndroidXRE    = regexp.MustCompile(`(?m)^\s*android\.useAndroidX\s*=\s*true\b`)
	androidXImportRE = regexp.MustCompile(`(?m)^\s*import\s+(androidx\.[\w.]+)`)
	supportImportRE  = regexp.MustCompile(`(?m)^\s*import\s+(android\.support\.[\w.]+)`)
)

// libraryEvidence is what the build files and sources say about the family.
type libraryEvidence struct {
	useAndroidX                   bool // gradle.properties sets android.useAndroidX=true
	buildAndroidX, buildSupport   bool // a build file declares androidx / com.android.support
	sourceAndroidX, sourceSupport bool // a source file imports androidx.* / android.support.*
}

// verdict turns the evidence into a family, or libUnknown when it is mixed or absent.
func (e libraryEvidence) verdict() androidLibrary {
	anyX := e.useAndroidX || e.buildAndroidX || e.sourceAndroidX
	anySupport := e.buildSupport || e.sourceSupport
	switch {
	case anyX && !anySupport:
		return libAndroidX
	case anySupport && !anyX:
		return libSupport
	}
	return libUnknown
}

// The family does not change during a run, and the gate asks once per patch.
var (
	androidLibraryMu    sync.Mutex
	androidLibraryCache = map[string]androidLibrary{}
)

// detectAndroidLibrary returns the family the repository at root builds against.
func detectAndroidLibrary(root string) androidLibrary {
	androidLibraryMu.Lock()
	defer androidLibraryMu.Unlock()
	if lib, ok := androidLibraryCache[root]; ok {
		return lib
	}
	lib := gatherLibraryEvidence(root).verdict()
	androidLibraryCache[root] = lib
	return lib
}

func gatherLibraryEvidence(root string) libraryEvidence {
	var e libraryEvidence
	eachBuildFile(root, func(body string) {
		e.buildAndroidX = e.buildAndroidX || strings.Contains(body, "androidx.")
		e.buildSupport = e.buildSupport || strings.Contains(body, "com.android.support")
	})
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && workspace.PruneDir(root, p) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		name := d.Name()
		ext := strings.ToLower(path.Ext(name))
		if name != "gradle.properties" && ext != ".java" && ext != ".kt" {
			return nil
		}
		body, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil
		}
		if name == "gradle.properties" {
			e.useAndroidX = e.useAndroidX || useAndroidXRE.Match(body)
			return nil
		}
		e.sourceAndroidX = e.sourceAndroidX || androidXImportRE.Match(body)
		e.sourceSupport = e.sourceSupport || supportImportRE.Match(body)
		return nil
	})
	return e
}

// checkAndroidLibraryImports refuses a Java or Kotlin patch that imports from
// the Android library family the project does not use.
func checkAndroidLibraryImports(root, p, original, patched string) *patchViolation {
	switch strings.ToLower(path.Ext(p)) {
	case ".java", ".kt":
	default:
		return nil
	}
	var wrong *regexp.Regexp
	var rule, have, lacks, right string
	switch detectAndroidLibrary(root) {
	case libSupport:
		wrong, rule = androidXImportRE, "androidx-in-support-project"
		have, lacks, right = "the Android Support Library (android.support.*)", "AndroidX", "android.support"
	case libAndroidX:
		wrong, rule = supportImportRE, "support-library-in-androidx-project"
		have, lacks, right = "AndroidX (androidx.*)", "the Android Support Library", "androidx"
	default:
		return nil
	}
	added := introduced(wrong, original, patched)
	if len(added) == 0 {
		return nil
	}
	imported := added[0][1]
	detail := fmt.Sprintf("%s imports %s, but this project uses %s and has no %s, so that class "+
		"does not exist here.", p, imported, have, lacks)
	if hint := sourceImportOf(root, simpleName(imported), right); hint != "" {
		detail += " The existing sources import it as " + hint + "; use that."
	} else {
		detail += " Use the " + right + ".* class the existing sources import, or leave it out."
	}
	return &patchViolation{Rule: rule, Detail: detail}
}

// simpleName is the class name an import ends with.
func simpleName(imported string) string {
	return imported[strings.LastIndex(imported, ".")+1:]
}

// sourceImportOf returns how an existing source file imports class name from
// the given package family, e.g. "android.support.v7.app.AppCompatActivity".
func sourceImportOf(root, name, family string) string {
	if name == "" || name == "*" {
		return ""
	}
	re := regexp.MustCompile(`(?m)^\s*import\s+(` + regexp.QuoteMeta(family) + `\.[\w.]*\.` +
		regexp.QuoteMeta(name) + `)\s*;?\s*$`)
	found := ""
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if d.IsDir() {
			if p != root && workspace.PruneDir(root, p) {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(path.Ext(p)) {
		case ".java", ".kt":
		default:
			return nil
		}
		if body, readErr := os.ReadFile(p); readErr == nil {
			if m := re.FindSubmatch(body); m != nil {
				found = string(m[1])
				return filepath.SkipAll
			}
		}
		return nil
	})
	return found
}

// libraryProfileLine states the family for the fix prompt, or "" when unknown.
func libraryProfileLine(lib androidLibrary) string {
	switch lib {
	case libSupport:
		return "Android library: Support Library (android.support.*), NOT AndroidX. " +
			"androidx.* classes do not exist here; import the android.support.* classes " +
			"the existing sources use."
	case libAndroidX:
		return "Android library: AndroidX (androidx.*). android.support.* classes do not " +
			"exist here; import the androidx.* classes the existing sources use."
	}
	return ""
}
