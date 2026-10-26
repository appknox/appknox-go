package helper

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/appknox/appknox-go/appknox"
)

// Finding → repo file + line, deterministically (no LLM). Ambiguous or
// missing → unresolved (the finding is skipped and listed in the PR body).

type locatedFinding struct {
	Ref  string
	Path string // repo-relative
	Line int    // 1-based anchor line
}

type repoIndex struct {
	root  string   // worktree root
	files []string // repo-relative paths, readable only
}

var testPathRe = regexp.MustCompile(`(?i)(^|/)(test|tests|androidTest|testDebug|testRelease|[^/]*Tests|[^/]*UITests|sample|samples|example|examples)(/|$)`)

func buildRepoIndex(root, appRoot string) (*repoIndex, error) {
	start := root
	if appRoot != "" {
		abs, err := absRepoPath(root, filepath.ToSlash(appRoot))
		if err != nil {
			return nil, err
		}
		start = abs
	}
	idx := &repoIndex{root: root}
	err := filepath.WalkDir(start, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != start && (skippedDirRe.MatchString(d.Name()) || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := repoRelPath(root, p)
		if err != nil || !isReadableRepoFile(rel) {
			return nil
		}
		idx.files = append(idx.files, rel)
		return nil
	})
	sort.Strings(idx.files)
	return idx, err
}

func (idx *repoIndex) match(globs []string) []string {
	for _, glob := range globs {
		re := globToRegexp(glob)
		var hits []string
		for _, f := range idx.files {
			if re.MatchString(f) {
				hits = append(hits, f)
			}
		}
		if len(hits) > 0 {
			return hits
		}
	}
	return nil
}

func (idx *repoIndex) read(rel string) (string, error) {
	abs, err := absRepoPath(idx.root, rel)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	return string(data), err
}

func withoutTests(paths []string) []string {
	var out []string
	for _, p := range paths {
		if !testPathRe.MatchString(p) {
			out = append(out, p)
		}
	}
	return out
}

// narrow picks one path, preferring non-test files, then (for config files)
// the conventional app module, then files that contain a search term.
func (idx *repoIndex) narrow(paths []string, preferred string, terms []string) string {
	if len(paths) == 1 {
		return paths[0]
	}
	if rest := withoutTests(paths); len(rest) > 0 {
		paths = rest
	}
	if len(paths) == 1 {
		return paths[0]
	}
	if preferred != "" {
		for _, p := range paths {
			if p == preferred {
				return p
			}
		}
	}
	if len(terms) > 0 {
		var containing []string
		for _, p := range paths {
			if content, err := idx.read(p); err == nil && strings.Contains(content, terms[0]) {
				containing = append(containing, p)
			}
		}
		if len(containing) == 1 {
			return containing[0]
		}
	}
	return "" // ambiguous
}

var nscAttrRe = regexp.MustCompile(`android:networkSecurityConfig\s*=\s*"@xml/([A-Za-z0-9_]+)"`)

func (idx *repoIndex) locateOne(f appknox.KnoxFixerPlanFinding) (string, bool) {
	loc := f.Locate
	switch loc.Kind {
	case "android_manifest":
		hits := idx.match(loc.PathGlobs)
		var main []string
		for _, h := range hits {
			if strings.HasSuffix(h, "src/main/AndroidManifest.xml") {
				main = append(main, h)
			}
		}
		if len(main) > 0 {
			hits = main
		}
		p := idx.narrow(hits, "app/src/main/AndroidManifest.xml", loc.SearchTerms)
		return p, p != ""
	case "android_network_security_config":
		if hits := idx.match(loc.PathGlobs); len(hits) > 0 {
			p := idx.narrow(hits, "", nil)
			return p, p != ""
		}
		// Resolve through the manifest attribute (custom file name).
		for _, manifest := range idx.match([]string{"**/src/main/AndroidManifest.xml"}) {
			content, err := idx.read(manifest)
			if err != nil {
				continue
			}
			if m := nscAttrRe.FindStringSubmatch(content); m != nil {
				dir := strings.TrimSuffix(manifest, "AndroidManifest.xml")
				candidate := dir + "res/xml/" + m[1] + ".xml"
				for _, f := range idx.files {
					if f == candidate {
						return f, true
					}
				}
			}
		}
		return "", false
	case "ios_plist":
		hits := withoutTests(idx.match(loc.PathGlobs))
		p := idx.narrow(hits, "", loc.SearchTerms)
		return p, p != ""
	default:
		hits := idx.match(loc.PathGlobs)
		p := idx.narrow(hits, "", nil)
		return p, p != ""
	}
}

// anchorLine: first line containing a search term (in hint order), else
// line 1.
func anchorLine(content string, terms []string) int {
	lines := strings.Split(content, "\n")
	for _, term := range terms {
		if term == "" {
			continue
		}
		for i, line := range lines {
			if strings.Contains(line, term) {
				return i + 1
			}
		}
	}
	return 1
}

// locateFindings returns located findings and unresolved refs.
func locateFindings(idx *repoIndex, findings []appknox.KnoxFixerPlanFinding) ([]locatedFinding, []string) {
	var located []locatedFinding
	var unresolved []string
	for _, f := range findings {
		p, ok := idx.locateOne(f)
		if !ok {
			unresolved = append(unresolved, f.Ref)
			continue
		}
		content, err := idx.read(p)
		if err != nil || isMinified(content) {
			unresolved = append(unresolved, f.Ref)
			continue
		}
		located = append(located, locatedFinding{Ref: f.Ref, Path: p, Line: anchorLine(content, f.Locate.SearchTerms)})
	}
	return located, unresolved
}

// isMinified: very long lines can't be sent as small snippets.
func isMinified(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		if len(line) > maxSnippetLineChars {
			return true
		}
	}
	return false
}
