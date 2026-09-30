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

// codeOnly returns the source with comments and string/char literals replaced
// by spaces (preserving newlines for line number stability). This prevents
// matching R references that appear only in comments or literals. With
// templates (Kotlin), a string's ${...} spans stay code: an R reference in
// one is compiled. A $name template holds no R reference and stays blank.
func codeOnly(src string, templates bool) string {
	var b strings.Builder
	codeSpan(src, 0, templates, false, &b)
	return b.String()
}

// codeSpan copies code from src[i:] to b, blanking comments and literals, and
// returns where it stopped: the end of src or, inTemplate, just past the '}'
// that closes a ${...} template.
func codeSpan(src string, i int, templates, inTemplate bool, b *strings.Builder) int {
	depth := 0
	for i < len(src) {
		switch {
		case strings.HasPrefix(src[i:], "//"):
			for i < len(src) && src[i] != '\n' {
				b.WriteByte(' ')
				i++
			}
		case strings.HasPrefix(src[i:], "/*"):
			i += 2
			b.WriteString("  ")
			for i < len(src) && !strings.HasPrefix(src[i:], "*/") {
				blankByte(b, src[i])
				i++
			}
			if i < len(src) {
				b.WriteString("  ")
				i += 2
			}
		case strings.HasPrefix(src[i:], `"""`):
			i = stringLit(src, i, `"""`, templates, b)
		case src[i] == '"':
			i = stringLit(src, i, `"`, templates, b)
		case src[i] == '\'':
			b.WriteByte(' ')
			i++
			for i < len(src) && src[i] != '\'' && src[i] != '\n' {
				if src[i] == '\\' {
					b.WriteString("  ")
					i += 2
					continue
				}
				b.WriteByte(' ')
				i++
			}
			if i < len(src) && src[i] == '\'' {
				b.WriteByte(' ')
				i++
			}
		case inTemplate && src[i] == '{':
			depth++
			b.WriteByte(src[i])
			i++
		case inTemplate && src[i] == '}':
			if depth == 0 {
				b.WriteByte(' ')
				return i + 1
			}
			depth--
			b.WriteByte(src[i])
			i++
		default:
			b.WriteByte(src[i])
			i++
		}
	}
	return i
}

// stringLit blanks the string literal opening at src[i] with quote (`"` or
// `"""`) and returns the index past it. A single-quoted string ends at a
// line end, like an unterminated one; with templates its ${...} spans are
// copied as code.
func stringLit(src string, i int, quote string, templates bool, b *strings.Builder) int {
	b.WriteString(strings.Repeat(" ", len(quote)))
	i += len(quote)
	raw := quote == `"""`
	for i < len(src) {
		switch {
		case strings.HasPrefix(src[i:], quote):
			b.WriteString(strings.Repeat(" ", len(quote)))
			return i + len(quote)
		case !raw && src[i] == '\n':
			return i
		case !raw && src[i] == '\\':
			b.WriteString("  ")
			i += 2
		case templates && strings.HasPrefix(src[i:], "${"):
			b.WriteString("  ")
			i = codeSpan(src, i+2, templates, true, b)
		default:
			blankByte(b, src[i])
			i++
		}
	}
	return i
}

// blankByte writes a space for c, or c itself when it is a newline.
func blankByte(b *strings.Builder, c byte) {
	if c == '\n' {
		b.WriteByte('\n')
		return
	}
	b.WriteByte(' ')
}

// introducedRRefs returns the R.<kind>.<name> references a Java/Kotlin patch
// adds that belong to this module's own R: not android.R, not another
// module's qualified R, not a file that imports a foreign R, and not a
// library resource.
func introducedRRefs(root, path, original, patched string) []resourceRef {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".java", ".kt":
	default:
		return nil
	}
	ns := moduleNamespace(root, moduleRoot(root, path))
	originalCode := codeOnly(original, ext == ".kt")
	patchedCode := codeOnly(patched, ext == ".kt")
	for _, m := range rImportRE.FindAllStringSubmatch(patchedCode, -1) {
		if m[1] != ns {
			return nil
		}
	}
	var out []resourceRef
	seen := map[string]bool{}
	// Build the set of refs that already exist in the original.
	originalRefs := map[string]bool{}
	for _, m := range rRefRE.FindAllStringSubmatch(originalCode, -1) {
		ref := m[1] + "R." + m[2] + "." + m[3]
		originalRefs[ref] = true
	}
	for _, m := range rRefRE.FindAllStringSubmatch(patchedCode, -1) {
		qual, kind, name := strings.TrimSuffix(m[1], "."), m[2], m[3]
		ref := m[1] + "R." + kind + "." + name
		if seen[ref] || originalRefs[ref] {
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

// wildcardImportRE finds `import <pkg>.*`, which brings that package's R into scope.
var wildcardImportRE = regexp.MustCompile(`(?m)^\s*import\s+([\w.]+)\.\*\s*;?\s*$`)

// checkRInScope rejects a patch that adds an unqualified R.<kind>.<name> to a
// class outside the module's namespace package without importing that R: the
// build generates R in the namespace package only, so the reference does not
// compile ("Unresolved reference 'R'") even when the resource exists. Enforced
// per file, never deferred: the fixer can always add the import itself.
func checkRInScope(root, path, original, patched string) *patchViolation {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".java" && ext != ".kt" {
		return nil
	}
	ref := firstNewUnqualifiedR(original, patched, ext == ".kt")
	if ref == "" {
		return nil
	}
	ns := moduleNamespace(root, moduleRoot(root, path))
	if ns == "" {
		return nil
	}
	m := packageDeclRE.FindStringSubmatch(patched)
	if m == nil || m[1] == ns {
		return nil
	}
	code := codeOnly(patched, ext == ".kt")
	// Any imported R is in scope; a foreign one is judged by introducedRRefs.
	if rImportRE.MatchString(code) {
		return nil
	}
	for _, w := range wildcardImportRE.FindAllStringSubmatch(code, -1) {
		if w[1] == ns {
			return nil
		}
	}
	semi := ""
	if ext == ".java" {
		semi = ";"
	}
	return &patchViolation{
		Rule: "r-not-imported",
		Detail: fmt.Sprintf("%s uses %s in package %s, but the build generates R in the module's namespace %s "+
			"only, so R is unresolved there. Add `import %s.R%s` below the package declaration.",
			path, ref, m[1], ns, ns, semi),
	}
}

// firstNewUnqualifiedR returns the first unqualified R.<kind>.<name> in the
// patched code that the original code does not already use, or "".
func firstNewUnqualifiedR(original, patched string, kotlin bool) string {
	had := map[string]bool{}
	for _, m := range rRefRE.FindAllStringSubmatch(codeOnly(original, kotlin), -1) {
		if m[1] == "" {
			had["R."+m[2]+"."+m[3]] = true
		}
	}
	for _, m := range rRefRE.FindAllStringSubmatch(codeOnly(patched, kotlin), -1) {
		if ref := "R." + m[2] + "." + m[3]; m[1] == "" && !had[ref] {
			return ref
		}
	}
	return ""
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
