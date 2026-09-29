package helper

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Reference checks: a patch may not introduce a reference to a resource or
// R entry nothing in the repository defines -- an AAPT or compile error that
// broke dvfa (@string), PeopleInSpace (R.layout), kgb_messenger and
// playstore-auth (@xml). Inside a unit these are deferred to the unit's
// resolve pass (unit_resolve.go), which completes what is missing.

// resourceRef is one reference: @kind/name in XML, R.kind.name in code.
type resourceRef struct {
	Kind, Name string
}

// introducedResourceRefs returns the @kind/name references an XML patch adds,
// library resources excepted.
func introducedResourceRefs(path, original, patched string) []resourceRef {
	if !strings.EqualFold(filepath.Ext(path), ".xml") {
		return nil
	}
	var out []resourceRef
	for _, m := range introduced(resourceRefRE, original, patched) {
		if !libraryResource(m[1], m[2]) {
			out = append(out, resourceRef{Kind: m[1], Name: m[2]})
		}
	}
	return out
}

// checkResourceRefs rejects a NEWLY ADDED reference to a resource nothing in
// the repository defines: no res/<kind>/<name>.* file and no values entry.
func checkResourceRefs(root, path, original, patched string) *patchViolation {
	refs := introducedResourceRefs(path, original, patched)
	if len(refs) == 0 {
		return nil
	}
	idx := buildResourceIndex(root)
	for _, r := range refs {
		if idx.has(r.Kind, r.Name) {
			continue
		}
		return &patchViolation{
			Rule: "missing-resource",
			Detail: fmt.Sprintf("%s adds a reference to @%s/%s, but nothing in this repository defines it, "+
				"and nothing in this remediation creates it. Use a resource that exists or write the literal "+
				"value in place, or make no edit.", path, r.Kind, r.Name),
		}
	}
	return nil
}

// rRefRE finds R.<kind>.<name> in Java/Kotlin, with any package qualifier in
// group 1 ("android." for the framework's, "com.x." for a module's own).
var rRefRE = regexp.MustCompile(`(?:^|[^\w.])((?:\w+\.)*)R\.(\w+)\.(\w+)`)

// rImportRE finds an import of some module's R class.
var rImportRE = regexp.MustCompile(`(?m)^\s*import\s+([\w.]+)\.R\s*;?\s*$`)

// rKindsUnchecked have no res/ entry to look up.
var rKindsUnchecked = map[string]bool{"styleable": true, "attr": true}

// introducedRRefs returns the R.<kind>.<name> references a Java/Kotlin patch
// adds that belong to this module's own R: not android.R, not another
// module's qualified R, not a file that imports a foreign R, and not a
// library resource.
func introducedRRefs(root, path, original, patched string) []resourceRef {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".java", ".kt":
	default:
		return nil
	}
	ns := moduleNamespace(root, moduleRoot(root, path))
	for _, m := range rImportRE.FindAllStringSubmatch(patched, -1) {
		if m[1] != ns {
			return nil
		}
	}
	var out []resourceRef
	seen := map[string]bool{}
	for _, m := range rRefRE.FindAllStringSubmatch(patched, -1) {
		qual, kind, name := strings.TrimSuffix(m[1], "."), m[2], m[3]
		ref := m[1] + "R." + kind + "." + name
		if seen[ref] || strings.Contains(original, ref) {
			continue
		}
		seen[ref] = true
		if qual == "android" || (qual != "" && qual != ns) || rKindsUnchecked[kind] || libraryResource(kind, name) {
			continue
		}
		out = append(out, resourceRef{Kind: kind, Name: name})
	}
	return out
}

// checkRReferences rejects a NEWLY ADDED R.<kind>.<name> that this module's
// resources do not define. The generated R class is judged by what it would
// contain, never by being on disk -- it never is.
func checkRReferences(root, path, original, patched string) *patchViolation {
	refs := introducedRRefs(root, path, original, patched)
	if len(refs) == 0 {
		return nil
	}
	idx := buildResourceIndex(root)
	for _, r := range refs {
		if idx.has(r.Kind, r.Name) {
			continue
		}
		return &patchViolation{
			Rule: "missing-r-reference",
			Detail: fmt.Sprintf("%s adds R.%s.%s, but this repository defines no %s named %s, and nothing "+
				"in this remediation creates it. Reference a resource that exists or write the literal value "+
				"in place, or make no edit.", path, r.Kind, r.Name, r.Kind, r.Name),
		}
	}
	return nil
}
