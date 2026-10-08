package helper

import (
	"encoding/xml"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/appknox/appknox-go/workspace"
)

// resourceIndex answers "does this repository define @kind/name, or class X?"
// for the patch gate and the unit resolve pass (spec 3.1). Each entry records
// the Gradle build that owns it (scopeOf): a repository can hold several
// independent apps (Damn-Vulnerable-React-Native's variant-a/b/c), and one
// app's resources are invisible to another's build. Within one build,
// lookups stay build-wide: flavour and library source sets count.
type resourceIndex struct {
	root    string
	defined map[string]map[string]bool // resKey(kind, name) -> owning scopes
	classes map[string]map[string]bool // fully qualified class name -> owning scopes
	scopes  map[string]string          // directory -> its scope, memoised
}

// resKey normalises a resource name the way aapt does, so @style/Theme.App
// and R.style.Theme_App are one key.
func resKey(kind, name string) string {
	return kind + "/" + strings.ReplaceAll(name, ".", "_")
}

// has and hasClass answer repository-wide, in any build.
func (x *resourceIndex) has(kind, name string) bool { return len(x.defined[resKey(kind, name)]) > 0 }

func (x *resourceIndex) hasClass(fqcn string) bool { return len(x.classes[fqcn]) > 0 }

// hasFrom and hasClassFrom answer for a reference in the file at rel: defined
// in that file's own Gradle build, or somewhere no build owns.
func (x *resourceIndex) hasFrom(rel, kind, name string) bool {
	return x.visible(x.defined[resKey(kind, name)], rel)
}

func (x *resourceIndex) hasClassFrom(rel, fqcn string) bool { return x.visible(x.classes[fqcn], rel) }

func (x *resourceIndex) visible(owners map[string]bool, rel string) bool {
	scope := x.scopeOf(rel)
	if scope == "" {
		return len(owners) > 0
	}
	return owners[scope] || owners[""]
}

// scopeOf returns the directory of the nearest settings.gradle(.kts) above
// rel ("." for the repository root), or "" when no Gradle build owns it.
func (x *resourceIndex) scopeOf(rel string) string {
	dir := path.Dir(filepath.ToSlash(rel))
	if s, ok := x.scopes[dir]; ok {
		return s
	}
	scope := ""
	for d := dir; ; d = path.Dir(d) {
		if fileExists(filepath.Join(x.root, d, "settings.gradle")) ||
			fileExists(filepath.Join(x.root, d, "settings.gradle.kts")) {
			scope = d
			break
		}
		if d == "." || d == "/" {
			break
		}
	}
	x.scopes[dir] = scope
	return scope
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// mark records key as defined in scope.
func mark(m map[string]map[string]bool, key, scope string) {
	if m[key] == nil {
		m[key] = map[string]bool{}
	}
	m[key][scope] = true
}

// resPathRE splits res/<kind>[-qualifier]/<file>. A .NET MAUI app keeps its
// Android resources in Platforms/Android/Resources/, which its build hands to
// aapt as res/.
var resPathRE = regexp.MustCompile(`(^|/)(?:res|Platforms/Android/Resources)/([a-z]+)(-[^/]+)?/([^/]+)$`)

// idDefRE finds an id a layout or menu declares.
var idDefRE = regexp.MustCompile(`@\+id/([A-Za-z0-9_.]+)`)

// classDeclRE finds class, interface, object, enum and record declarations,
// nested ones and those behind same-line annotations (@Keep, @AndroidEntryPoint,
// @SuppressWarnings("x")) included: over-counting a class only makes a
// completion less likely, and a completion that duplicates a class breaks the
// build. Kotlin's `enum class` reads enum as a modifier.
var classDeclRE = regexp.MustCompile(`(?m)^\s*(?:(?:@[\w.]+(?:\([^)\n]*\))?|public|private|protected|internal|` +
	`abstract|final|open|sealed|data|enum|annotation|inner|static|value)\s+)*` +
	`(?:class|interface|object|@interface|record|enum)\s+(\w+)`)

// valuesKinds maps a res/values element to the R kind it defines.
var valuesKinds = map[string]string{
	"string": "string", "dimen": "dimen", "color": "color", "bool": "bool", "integer": "integer",
	"string-array": "array", "integer-array": "array", "array": "array", "plurals": "plurals",
	"fraction": "fraction", "style": "style", "attr": "attr", "declare-styleable": "styleable",
	"drawable": "drawable",
}

// buildResourceIndex walks the checkout once, skipping what workspace.PruneDir
// skips (build output, vendored trees, nested repositories).
func buildResourceIndex(root string) *resourceIndex {
	x := &resourceIndex{root: root, defined: map[string]map[string]bool{},
		classes: map[string]map[string]bool{}, scopes: map[string]string{}}
	mark(x.defined, resKey("integer", "google_play_services_version"), "")
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			if workspace.PruneDir(root, p) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		x.add(p, filepath.ToSlash(rel))
		return nil
	})
	return x
}

// add indexes one file: a source file's classes, a values file's entries, or
// a file resource by its name, plus the ids an XML resource declares.
func (x *resourceIndex) add(abs, rel string) {
	scope := x.scopeOf(rel)
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".java", ".kt":
		x.addClasses(abs, scope)
		return
	}
	switch path.Base(rel) {
	case "build.gradle", "build.gradle.kts":
		x.addScript(abs, scope)
		return
	case "google-services.json":
		x.addGoogleServices(scope)
		return
	}
	m := resPathRE.FindStringSubmatch(rel)
	if m == nil {
		return
	}
	kind, base := m[2], m[4]
	if kind == "values" {
		x.addValues(abs, scope)
		return
	}
	// Named before the first dot: bg.9.png is @drawable/bg.
	mark(x.defined, resKey(kind, strings.SplitN(base, ".", 2)[0]), scope)
	if strings.HasSuffix(base, ".xml") {
		x.addIDs(abs, scope)
	}
}

// resValueRE finds resValue "kind", "name", "value" (Groovy) and
// resValue("kind", "name", "value") (Kotlin DSL) in a module build script.
var resValueRE = regexp.MustCompile(`\bresValue\s*\(?\s*["'](\w+)["']\s*,\s*["']([\w.]+)["']`)

// googleServicesPluginRE finds the google-services plugin applied in a script.
var googleServicesPluginRE = regexp.MustCompile(`["']com\.google\.gms\.google-services["']`)

// googleServicesStrings are the string resources the google-services plugin
// generates from google-services.json.
var googleServicesStrings = []string{"default_web_client_id", "google_app_id", "gcm_defaultSenderId",
	"google_api_key", "google_crash_reporting_api_key", "google_storage_bucket", "project_id",
	"firebase_database_url"}

// addScript indexes what a module build script generates: its resValue
// entries, and the google-services strings when it applies that plugin.
func (x *resourceIndex) addScript(abs, scope string) {
	b, err := os.ReadFile(abs)
	if err != nil {
		return
	}
	for _, m := range resValueRE.FindAllSubmatch(b, -1) {
		mark(x.defined, resKey(string(m[1]), string(m[2])), scope)
	}
	if googleServicesPluginRE.Match(b) {
		x.addGoogleServices(scope)
	}
}

// addGoogleServices marks the google-services strings defined: a repository
// with a google-services.json, or applying the plugin, gets them generated.
func (x *resourceIndex) addGoogleServices(scope string) {
	for _, n := range googleServicesStrings {
		mark(x.defined, resKey("string", n), scope)
	}
}

func (x *resourceIndex) addIDs(abs, scope string) {
	b, err := os.ReadFile(abs)
	if err != nil {
		return
	}
	for _, m := range idDefRE.FindAllSubmatch(b, -1) {
		mark(x.defined, resKey("id", string(m[1])), scope)
	}
}

func (x *resourceIndex) addClasses(abs, scope string) {
	b, err := os.ReadFile(abs)
	if err != nil {
		return
	}
	pkg := ""
	if m := packageDeclRE.FindSubmatch(b); m != nil {
		pkg = string(m[1]) + "."
	}
	for _, m := range classDeclRE.FindAllSubmatch(b, -1) {
		mark(x.classes, pkg+string(m[1]), scope)
	}
}

// addValues reads the direct children of <resources>. The decoder is not
// strict, so an entity a DOCTYPE declares (&appname;) does not stop it; a
// file that still stops parsing keeps what was read before the error, and
// the build judges the rest.
func (x *resourceIndex) addValues(abs, scope string) {
	f, err := os.Open(abs)
	if err != nil {
		return
	}
	defer f.Close()
	dec := xml.NewDecoder(f)
	dec.Strict = false
	dec.Entity = xml.HTMLEntity
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 {
				x.addValue(t, scope)
			}
		case xml.EndElement:
			depth--
		}
	}
}

func (x *resourceIndex) addValue(el xml.StartElement, scope string) {
	name, typ := "", ""
	for _, a := range el.Attr {
		switch a.Name.Local {
		case "name":
			name = a.Value
		case "type":
			typ = a.Value
		}
	}
	kind := valuesKinds[el.Name.Local]
	if el.Name.Local == "item" {
		kind = typ
	}
	if kind != "" && name != "" {
		mark(x.defined, resKey(kind, name), scope)
	}
}

// libraryResourcePrefixes name resources that AndroidX, Material and Play
// services ship. Apps reference them freely and they are not in the checkout,
// so a reference to one is never reported and never "completed": redefining
// a library resource overrides it for the whole app.
var libraryResourcePrefixes = []string{"abc_", "material_", "mtrl_", "design_", "m3_", "m3c_",
	"common_google_", "androidx_", "exo_", "com_facebook_"}

// libraryStylePrefixes are the same for styles, in R form (dots as underscores).
var libraryStylePrefixes = []string{"Theme_AppCompat", "Theme_MaterialComponents", "Theme_Material3",
	"Theme_Design", "ThemeOverlay_", "Widget_", "TextAppearance_", "Base_", "Platform_",
	"ShapeAppearance_", "Animation_AppCompat", "Theme_SplashScreen", "AlertDialog_AppCompat"}

func libraryResource(kind, name string) bool {
	n := strings.ReplaceAll(name, ".", "_")
	prefixes := libraryResourcePrefixes
	if kind == "style" {
		prefixes = libraryStylePrefixes
	}
	for _, p := range prefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}
