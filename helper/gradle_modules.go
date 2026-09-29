package helper

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Gradle module facts the gate needs without running Gradle: which module a
// file belongs to, that module's namespace, and which library modules it
// pulls in through project(':x').

var moduleScripts = []string{"build.gradle", "build.gradle.kts"}

// moduleRoot returns the repository-relative directory of the Gradle module
// holding rel: the nearest ancestor with a build.gradle(.kts), "." for the
// repository root, and "" when no ancestor has one (a non-Gradle tree).
func moduleRoot(root, rel string) string {
	dir := path.Dir(filepath.ToSlash(rel))
	for {
		for _, s := range moduleScripts {
			if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(dir), s)); err == nil && !info.IsDir() {
				return dir
			}
		}
		if dir == "." || dir == "/" {
			return ""
		}
		dir = path.Dir(dir)
	}
}

// readModuleScript returns a module's build script, or "" when it has none.
func readModuleScript(root, module string) string {
	if module == "" {
		return ""
	}
	for _, s := range moduleScripts {
		if b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(module), s)); err == nil {
			return string(b)
		}
	}
	return ""
}

// namespaceRE matches `namespace 'a.b'` (Groovy) and `namespace = "a.b"` (Kotlin DSL).
var namespaceRE = regexp.MustCompile(`(?m)^\s*namespace\s*=?\s*["']([\w.]+)["']`)

// manifestPackageRE is the pre-AGP-7 way to name the R package.
var manifestPackageRE = regexp.MustCompile(`<manifest\b[^>]*\bpackage\s*=\s*"([\w.]+)"`)

// moduleNamespace is the package of the module's generated R: the build
// script's namespace, else its main manifest's package=, else "".
func moduleNamespace(root, module string) string {
	if module == "" {
		return ""
	}
	if m := namespaceRE.FindStringSubmatch(readModuleScript(root, module)); m != nil {
		return m[1]
	}
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(module), "src", "main", "AndroidManifest.xml"))
	if err != nil {
		return ""
	}
	if m := manifestPackageRE.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

// projectDepRE finds project(':x') and project(path: ':x') dependencies.
var projectDepRE = regexp.MustCompile(`project\(\s*(?:path\s*[:=]\s*)?["'](:[\w.:-]+)["']`)

// projectDirRE finds a settings-file remap: project(':x').projectDir = new File(rootDir, 'dir').
var projectDirRE = regexp.MustCompile(`project\(\s*["'](:[\w.:-]+)["']\s*\)\.projectDir\s*=\s*` +
	`(?:new\s+)?(?:File|file)\(\s*(?:(?:rootDir|settingsDir|rootProject\.projectDir)\s*,\s*)?["']([^"']+)["']`)

// projectDeps returns the module dirs that module depends on through
// project(':x'), resolved through settings.gradle(.kts) projectDir remaps;
// an unmapped ':a:b' is the directory a/b.
func projectDeps(root, module string) map[string]bool {
	out := map[string]bool{}
	script := readModuleScript(root, module)
	if script == "" {
		return out
	}
	dirs := projectDirs(root)
	for _, m := range projectDepRE.FindAllStringSubmatch(script, -1) {
		if d, ok := dirs[m[1]]; ok {
			out[d] = true
			continue
		}
		out[strings.ReplaceAll(strings.TrimPrefix(m[1], ":"), ":", "/")] = true
	}
	return out
}

func projectDirs(root string) map[string]string {
	out := map[string]string{}
	for _, s := range []string{"settings.gradle", "settings.gradle.kts"} {
		b, err := os.ReadFile(filepath.Join(root, s))
		if err != nil {
			continue
		}
		for _, m := range projectDirRE.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = path.Clean(m[2])
		}
	}
	return out
}
