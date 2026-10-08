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
// pulls in through project(':x') or a projects.x accessor.

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

// projectAccessorRE finds a type-safe project accessor: projects.core,
// projects.featureLogin, projects.feature.login (Kotlin DSL and Groovy).
var projectAccessorRE = regexp.MustCompile(`\bprojects((?:\.\w+)+)`)

// projectDirRE finds a settings-file remap: project(':x').projectDir = new File(rootDir, 'dir').
var projectDirRE = regexp.MustCompile(`project\(\s*["'](:[\w.:-]+)["']\s*\)\.projectDir\s*=\s*` +
	`(?:new\s+)?(?:File|file)\(\s*(?:(?:rootDir|settingsDir|rootProject\.projectDir)\s*,\s*)?["']([^"']+)["']`)

// includeRE finds an include statement in a settings file; includeNameRE the
// project paths it names, which may continue over lines ending in a comma.
var (
	includeRE     = regexp.MustCompile(`(?m)^\s*include\b[^\n]*(?:,\s*\n[^\n]*)*`)
	includeNameRE = regexp.MustCompile(`["'](:?[\w.:-]+)["']`)
)

// gradleSettings holds what settings.gradle(.kts) says about module paths.
type gradleSettings struct {
	dirs      map[string]string // ':x' -> directory, from projectDir remaps
	accessors map[string]string // 'feature.login' -> ':feature:login', from include
}

func readGradleSettings(root string) gradleSettings {
	g := gradleSettings{dirs: map[string]string{}, accessors: map[string]string{}}
	for _, s := range []string{"settings.gradle", "settings.gradle.kts"} {
		b, err := os.ReadFile(filepath.Join(root, s))
		if err != nil {
			continue
		}
		for _, m := range projectDirRE.FindAllStringSubmatch(string(b), -1) {
			g.dirs[m[1]] = path.Clean(m[2])
		}
		for _, inc := range includeRE.FindAllString(string(b), -1) {
			for _, m := range includeNameRE.FindAllStringSubmatch(inc, -1) {
				p := ":" + strings.TrimPrefix(m[1], ":")
				g.accessors[projectAccessor(p)] = p
			}
		}
	}
	for p := range g.dirs {
		g.accessors[projectAccessor(p)] = p
	}
	return g
}

// projectAccessor is Gradle's type-safe accessor for a project path:
// ':feature-login' is featureLogin, ':feature:login' is feature.login.
func projectAccessor(projectPath string) string {
	segs := strings.Split(strings.TrimPrefix(projectPath, ":"), ":")
	for i, seg := range segs {
		words := strings.FieldsFunc(seg, func(r rune) bool { return r == '-' || r == '_' })
		for j := 1; j < len(words); j++ {
			words[j] = strings.ToUpper(words[j][:1]) + words[j][1:]
		}
		segs[i] = strings.Join(words, "")
	}
	return strings.Join(segs, ".")
}

// dir is the directory of a project path: its projectDir remap, else ':a:b' is a/b.
func (g gradleSettings) dir(projectPath string) string {
	if d, ok := g.dirs[projectPath]; ok {
		return d
	}
	return strings.ReplaceAll(strings.TrimPrefix(projectPath, ":"), ":", "/")
}

// accessorPath resolves projects.a.b.c to the longest included project path
// it names (a trailing segment may be a property such as dependencyProject).
func (g gradleSettings) accessorPath(accessor string) (string, bool) {
	segs := strings.Split(strings.TrimPrefix(accessor, "."), ".")
	for n := len(segs); n > 0; n-- {
		if p, ok := g.accessors[strings.Join(segs[:n], ".")]; ok {
			return p, true
		}
	}
	return "", false
}

// projectDeps returns the module dirs that module depends on directly through
// project(':x') or a projects.x accessor, resolved through
// settings.gradle(.kts); an unmapped ':a:b' is the directory a/b.
func projectDeps(root, module string) map[string]bool {
	deps, _ := directDeps(root, module, readGradleSettings(root))
	return deps
}

// directDeps is projectDeps with the settings read once; ok is false when the
// script names an accessor the settings do not include.
func directDeps(root, module string, g gradleSettings) (map[string]bool, bool) {
	out := map[string]bool{}
	script := readModuleScript(root, module)
	if script == "" {
		return out, true
	}
	for _, m := range projectDepRE.FindAllStringSubmatch(script, -1) {
		out[g.dir(m[1])] = true
	}
	ok := true
	for _, m := range projectAccessorRE.FindAllStringSubmatch(script, -1) {
		p, found := g.accessorPath(m[1])
		if !found {
			ok = false
			continue
		}
		out[g.dir(p)] = true
	}
	return out, ok
}

// depClosure returns every module module pulls in, transitively: AGP merges a
// library's library manifests into the app too. ok is false when some script
// on the way names a dependency that cannot be resolved.
func depClosure(root, module string, g gradleSettings) (map[string]bool, bool) {
	seen := map[string]bool{}
	ok := true
	queue := []string{module}
	for len(queue) > 0 {
		m := queue[0]
		queue = queue[1:]
		deps, resolved := directDeps(root, m, g)
		ok = ok && resolved
		for d := range deps {
			if !seen[d] && d != module {
				seen[d] = true
				queue = append(queue, d)
			}
		}
	}
	return seen, ok
}

// mergesWith reports whether AGP merges the manifest at other with the one at
// patched: the same module (any source set), or a library module either one
// pulls in, transitively, through project(':x') or a projects.x accessor.
// Two manifests outside Gradle in different .NET projects (.csproj) merge only
// when one project references the other. A manifest outside any build, or a
// module whose dependencies cannot all be resolved, is assumed to merge with
// everything -- the conservative behaviour (spec 3.3).
func mergesWith(root, patched, other string) bool {
	pm, om := moduleRoot(root, patched), moduleRoot(root, other)
	if pm == "" && om == "" {
		return dotnetMerges(root, patched, other)
	}
	if pm == "" || om == "" || pm == om {
		return true
	}
	g := readGradleSettings(root)
	pdeps, pok := depClosure(root, pm, g)
	odeps, ook := depClosure(root, om, g)
	return !pok || !ook || pdeps[om] || odeps[pm]
}

// dotnetProject returns the nearest .csproj above rel, relative to root, or ""
// when none does.
func dotnetProject(root, rel string) string {
	dir := path.Dir(filepath.ToSlash(rel))
	for {
		if matches, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(dir), "*.csproj")); len(matches) == 1 {
			p, _ := filepath.Rel(root, matches[0])
			return filepath.ToSlash(p)
		} else if len(matches) > 1 {
			return "" // several projects share the directory; cannot tell which owns rel
		}
		if dir == "." || dir == "/" {
			return ""
		}
		dir = path.Dir(dir)
	}
}

// projectReferenceRE finds a ProjectReference's Include path.
var projectReferenceRE = regexp.MustCompile(`<ProjectReference\s+Include\s*=\s*"([^"]+)"`)

// dotnetMerges reports whether the manifests at a and b build into one app:
// the same .csproj, or one project referencing the other. Without a .csproj
// for either, it assumes they do.
func dotnetMerges(root, a, b string) bool {
	pa, pb := dotnetProject(root, a), dotnetProject(root, b)
	if pa == "" || pb == "" || pa == pb {
		return true
	}
	return referencesProject(root, pa, pb) || referencesProject(root, pb, pa)
}

// referencesProject reports whether project from names project to in a
// ProjectReference. An unreadable project is assumed to.
func referencesProject(root, from, to string) bool {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(from)))
	if err != nil {
		return true
	}
	for _, m := range projectReferenceRE.FindAllSubmatch(b, -1) {
		ref := path.Clean(path.Join(path.Dir(from), strings.ReplaceAll(string(m[1]), "\\", "/")))
		if ref == to {
			return true
		}
	}
	return false
}
