package helper

import (
	"encoding/xml"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/appknox/appknox-go/agent"
)

// resourceIndex answers "does this repository define @kind/name, or class X?"
// for the patch gate and the unit resolve pass (spec 3.1). Lookups are
// repository-wide, like resourceExists before it: flavour and library source
// sets count, not only the referencing module's main set.
type resourceIndex struct {
	defined map[string]bool // resKey(kind, name)
	classes map[string]bool // fully qualified names declared in .java/.kt sources
}

// resKey normalises a resource name the way aapt does, so @style/Theme.App
// and R.style.Theme_App are one key.
func resKey(kind, name string) string {
	return kind + "/" + strings.ReplaceAll(name, ".", "_")
}

func (x *resourceIndex) has(kind, name string) bool { return x.defined[resKey(kind, name)] }

func (x *resourceIndex) hasClass(fqcn string) bool { return x.classes[fqcn] }

// resPathRE splits res/<kind>[-qualifier]/<file>.
var resPathRE = regexp.MustCompile(`(^|/)res/([a-z]+)(-[^/]+)?/([^/]+)$`)

// idDefRE finds an id a layout or menu declares.
var idDefRE = regexp.MustCompile(`@\+id/([A-Za-z0-9_.]+)`)

// classDeclRE finds class, interface and object declarations, nested ones
// included: over-counting a class only makes a completion less likely, and a
// completion that duplicates a class breaks the build.
var classDeclRE = regexp.MustCompile(`(?m)^\s*(?:(?:public|private|protected|internal|abstract|final|open|` +
	`sealed|data|enum|annotation|inner|static|value)\s+)*(?:class|interface|object|@interface)\s+(\w+)`)

// valuesKinds maps a res/values element to the R kind it defines.
var valuesKinds = map[string]string{
	"string": "string", "dimen": "dimen", "color": "color", "bool": "bool", "integer": "integer",
	"string-array": "array", "integer-array": "array", "array": "array", "plurals": "plurals",
	"fraction": "fraction", "style": "style", "attr": "attr", "declare-styleable": "styleable",
}

// buildResourceIndex walks the checkout once, skipping what agent.PruneDir
// skips (build output, vendored trees, nested repositories).
func buildResourceIndex(root string) *resourceIndex {
	x := &resourceIndex{defined: map[string]bool{}, classes: map[string]bool{}}
	x.defined[resKey("integer", "google_play_services_version")] = true
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			if agent.PruneDir(root, p) {
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
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".java", ".kt":
		x.addClasses(abs)
		return
	}
	switch path.Base(rel) {
	case "build.gradle", "build.gradle.kts":
		x.addScript(abs)
		return
	case "google-services.json":
		x.addGoogleServices()
		return
	}
	m := resPathRE.FindStringSubmatch(rel)
	if m == nil {
		return
	}
	kind, base := m[2], m[4]
	if kind == "values" {
		x.addValues(abs)
		return
	}
	// Named before the first dot: bg.9.png is @drawable/bg.
	x.defined[resKey(kind, strings.SplitN(base, ".", 2)[0])] = true
	if strings.HasSuffix(base, ".xml") {
		x.addIDs(abs)
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
func (x *resourceIndex) addScript(abs string) {
	b, err := os.ReadFile(abs)
	if err != nil {
		return
	}
	for _, m := range resValueRE.FindAllSubmatch(b, -1) {
		x.defined[resKey(string(m[1]), string(m[2]))] = true
	}
	if googleServicesPluginRE.Match(b) {
		x.addGoogleServices()
	}
}

// addGoogleServices marks the google-services strings defined: a repository
// with a google-services.json, or applying the plugin, gets them generated.
func (x *resourceIndex) addGoogleServices() {
	for _, n := range googleServicesStrings {
		x.defined[resKey("string", n)] = true
	}
}

func (x *resourceIndex) addIDs(abs string) {
	b, err := os.ReadFile(abs)
	if err != nil {
		return
	}
	for _, m := range idDefRE.FindAllSubmatch(b, -1) {
		x.defined[resKey("id", string(m[1]))] = true
	}
}

func (x *resourceIndex) addClasses(abs string) {
	b, err := os.ReadFile(abs)
	if err != nil {
		return
	}
	pkg := ""
	if m := packageDeclRE.FindSubmatch(b); m != nil {
		pkg = string(m[1]) + "."
	}
	for _, m := range classDeclRE.FindAllSubmatch(b, -1) {
		x.classes[pkg+string(m[1])] = true
	}
}

// addValues reads the direct children of <resources>. A file that stops
// parsing keeps what was read before the error; the build judges the rest.
func (x *resourceIndex) addValues(abs string) {
	f, err := os.Open(abs)
	if err != nil {
		return
	}
	defer f.Close()
	dec := xml.NewDecoder(f)
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
				x.addValue(t)
			}
		case xml.EndElement:
			depth--
		}
	}
}

func (x *resourceIndex) addValue(el xml.StartElement) {
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
		x.defined[resKey(kind, name)] = true
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
