package helper

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// The Android platform jar, read as a fact on disk.
//
// verify_patch.go draws a line at what the filesystem can decide, and dropped
// the old unresolved-import check for crossing it: the Gradle dependency graph
// is not on disk, so nothing here can know whether timber.log.Timber resolves.
//
// android.jar is the exception. It ships with the SDK, it sits on the runner --
// the corpus repos build with actions/setup-java alone, no SDK install step, so
// the image already carries it -- and it is the complete and authoritative list
// of what android.* declares. That is a filesystem fact, not a compiler one.
//
// It answers a failure this gate watched happen. Fossify Calendar, 2026-09-11:
// the fixer wrote Intent.ACTION_TIME_SET, which does not exist. The constant is
// named ACTION_TIME_CHANGED and its *value* is "android.intent.action.TIME_SET"
// -- name and value disagree, and the fixer read the value as the name. No
// amount of prompting fixes a model reading a real string out of real docs; a
// lookup does.
//
// TWO ABSTENTIONS, both deliberate:
//
//  1. NO SDK, NO OPINION. A machine without a platform jar answers nothing and
//     the patch passes. The gate is a guard, not a requirement.
//
//  2. PRESENCE PROVES NOTHING; ABSENCE PROVES EVERYTHING. The check asks only
//     whether a name occurs in a class file's bytes. If it does not occur, the
//     member certainly does not exist. If it does occur it may be a field, a
//     method, or an unrelated string -- so a hit is treated as "cannot tell"
//     and accepted. That asymmetry is why this needs no class-file parser.

// androidImportRE captures a single-class import of an android.* type. The
// trailing semicolon is optional so the same expression reads Kotlin.
var androidImportRE = regexp.MustCompile(`(?m)^\s*import\s+(android\.[\w.]+?)\s*;?\s*$`)

// platformConstRE matches a SCREAMING_CASE member read off a class name, e.g.
// Intent.ACTION_TIME_SET. Three characters minimum, so single-letter noise and
// enum-ish two-letter pairs do not enter the lookup.
var platformConstRE = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*)\.([A-Z][A-Z0-9_]{2,})\b`)

// checkAndroidSymbols rejects a NEWLY ADDED reference to an android.* member
// the platform jar does not contain.
func checkAndroidSymbols(root, path, original, patched string) *patchViolation {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".java", ".kt":
	default:
		return nil
	}
	refs := introduced(platformConstRE, original, patched)
	if len(refs) == 0 {
		return nil
	}
	imports := androidImports(patched)
	if len(imports) == 0 {
		return nil
	}
	jar, ok := openAndroidJar(root)
	if !ok {
		return nil // abstention 1: no usable platform jar, no opinion
	}
	defer jar.close()

	for _, m := range refs {
		class, member := m[1], m[2]
		fqcn, imported := imports[class]
		if !imported {
			continue // not a platform class; the jar has no say
		}
		if !jar.missing(fqcn, member) {
			continue
		}
		return &patchViolation{
			Rule: "unknown-android-symbol",
			Detail: fmt.Sprintf("%s.%s does not exist: %s declares no such member in the "+
				"Android platform. Check the exact constant name in the SDK -- a constant's "+
				"name and its string value often differ -- then use the real one, or make "+
				"no edit.", class, member, fqcn),
		}
	}
	return nil
}

// androidImports maps each imported simple class name to its android.* FQCN.
//
// Wildcards are skipped: "import android.content.*" names no class, so nothing
// can be looked up through it.
func androidImports(src string) map[string]string {
	out := map[string]string{}
	for _, m := range androidImportRE.FindAllStringSubmatch(src, -1) {
		fq := m[1]
		if strings.HasSuffix(fq, ".*") {
			continue
		}
		out[fq[strings.LastIndex(fq, ".")+1:]] = fq
	}
	return out
}

// androidJar is an opened platform jar.
type androidJar struct{ zr *zip.ReadCloser }

// openAndroidJar opens the platform jar to judge this repository against.
func openAndroidJar(root string) (*androidJar, bool) {
	p := androidJarFor(root)
	if p == "" {
		return nil, false
	}
	zr, err := zip.OpenReader(p)
	if err != nil {
		return nil, false
	}
	return &androidJar{zr: zr}, true
}

func (j *androidJar) close() { _ = j.zr.Close() }

// missing reports whether the member is certainly absent from the class.
//
// False whenever the jar cannot answer -- class not carried, entry unreadable
// -- and false when the name turns up anywhere else in the jar, because a
// constant declared by a supertype lives in the SUPERTYPE's class file:
// AlertDialog.BUTTON_POSITIVE is declared on DialogInterface, and checking only
// AlertDialog.class would reject a perfectly legal reference.
func (j *androidJar) missing(fqcn, member string) bool {
	f := j.entry(strings.ReplaceAll(fqcn, ".", "/") + ".class")
	if f == nil {
		return false
	}
	b, err := readZipEntry(f)
	if err != nil {
		return false
	}
	needle := []byte(member)
	if bytes.Contains(b, needle) {
		return false
	}
	return !j.mentionedAnywhere(needle)
}

// entry returns the named zip entry, or nil.
func (j *androidJar) entry(name string) *zip.File {
	for _, f := range j.zr.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// mentionedAnywhere reports whether the name occurs in any class in the jar.
//
// COSTS ~150ms, and is NOT rare. It runs whenever the direct class lookup
// misses, which includes the entirely legitimate inherited-constant case that
// then goes on to be ACCEPTED -- AlertDialog.BUTTON_POSITIVE and every other
// constant reached through a supertype pays for it. Android patches touch those
// often, so treat this as a cost of the check rather than a rejection-path
// rarity. It is still cheaper than wrongly discarding a fix, which is the
// alternative; if it ever needs to be faster, index the jar once per run
// instead of scanning it per file.
func (j *androidJar) mentionedAnywhere(needle []byte) bool {
	for _, f := range j.zr.File {
		if !strings.HasSuffix(f.Name, ".class") {
			continue
		}
		b, err := readZipEntry(f)
		if err != nil {
			continue
		}
		if bytes.Contains(b, needle) {
			return true
		}
	}
	return false
}

// readZipEntry reads one entry fully into memory.
func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// androidJarFor returns the platform jar to judge this repository against, or
// "" to abstain.
//
// WHICH jar matters, and picking the newest installed one is not safe. The SDK
// on the runner is provisioned independently of what any repo compiles against:
// if the newest platform installed is OLDER than the repo's compileSdk, then a
// constant introduced in a later API is missing from the jar, missing from the
// whole-jar scan too, and a correct patch is rejected. That is exactly the
// failure this gate exists to prevent, so that case abstains instead.
//
// A jar NEWER than compileSdk is a superset and stays safe: everything the repo
// can legally reference is still in it. The residual risk there is a constant
// removed in a later platform, which is rare enough to accept and cheap to
// notice -- the alternative is a check that only ever runs on an exact match.
func androidJarFor(root string) string {
	installed := installedPlatforms()
	if len(installed) == 0 {
		return ""
	}
	newest := -1
	for level := range installed {
		if level > newest {
			newest = level
		}
	}
	want := repoCompileSdk(root)
	switch {
	case want <= 0:
		return installed[newest] // no compileSdk found; the fullest jar we have
	case installed[want] != "":
		return installed[want] // exactly what the repo compiles against
	case newest < want:
		return "" // our jar predates the repo's API; we cannot judge it
	default:
		return installed[newest] // a superset of what the repo may reference
	}
}

// installedPlatforms maps API level to platform jar across both SDK variables.
func installedPlatforms() map[int]string {
	out := map[int]string{}
	for _, env := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		home := os.Getenv(env)
		if home == "" {
			continue
		}
		matches, err := filepath.Glob(filepath.Join(home, "platforms", "android-*", "android.jar"))
		if err != nil {
			continue
		}
		for _, m := range matches {
			level := platformLevel(filepath.Base(filepath.Dir(m)))
			if _, seen := out[level]; !seen {
				out[level] = m
			}
		}
	}
	return out
}

// platformLevel reads the API level out of an "android-34" directory name.
//
// A named preview ("android-VanillaIceCream") scores 0: usable if it is all
// there is, never preferred over a numbered release.
func platformLevel(dir string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(dir, "android-"))
	if err != nil {
		return 0
	}
	return n
}
