package helper

import (
	"fmt"
	"path/filepath"
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
