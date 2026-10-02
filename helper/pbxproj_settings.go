package helper

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Xcode build settings live in project.pbxproj, a file no model edits well:
// wikipedia-ios's is 1.36 MB (read_file caps at 256 KB) and holds 117 build
// configurations whose lines repeat verbatim, so a text edit cannot say which
// one it means. So code edits it: the remediation names hardening settings,
// each is set to the one value hardenedSettings holds, in the Release
// configurations of the app targets only. The model is never asked for a value.

// hardenedSettings are the build settings a remediation may change, each with
// the only value autofix writes. A remediation naming any other setting, or
// asking for another value, gets no edit for it.
var hardenedSettings = map[string]string{
	"STRIP_INSTALLED_PRODUCT":    "YES",
	"STRIP_SWIFT_SYMBOLS":        "YES",
	"STRIP_STYLE":                "all",
	"DEPLOYMENT_POSTPROCESSING":  "YES",
	"COPY_PHASE_STRIP":           "YES",
	"DEAD_CODE_STRIPPING":        "YES",
	"DEBUG_INFORMATION_FORMAT":   "dwarf-with-dsym",
	"SWIFT_OPTIMIZATION_LEVEL":   "-O",
	"GCC_OPTIMIZATION_LEVEL":     "s",
	"SWIFT_COMPILATION_MODE":     "wholemodule",
	"ENABLE_TESTABILITY":         "NO",
	"ENABLE_NS_ASSERTIONS":       "NO",
	"GCC_SYMBOLS_PRIVATE_EXTERN": "YES",
	"VALIDATE_PRODUCT":           "YES",
}

// projectFileRE matches an Xcode project's project file.
var projectFileRE = regexp.MustCompile(`(^|/)[^/]+\.xcodeproj/project\.pbxproj$`)

// isProjectFile reports a first-party Xcode project file: CocoaPods generates
// Pods/Pods.xcodeproj on every install, so that one is never a target.
func isProjectFile(rel string) bool {
	rel = strings.TrimPrefix(path.Clean("/"+rel), "/")
	return projectFileRE.MatchString(rel) && !strings.HasPrefix(rel, "Pods/") && !strings.Contains(rel, "/Pods/")
}

var settingNameRE = regexp.MustCompile(`\b[A-Z][A-Z0-9_]{2,}\b`)

// namedBuildSettings returns the hardenedSettings keys text names, in order of
// first mention.
func namedBuildSettings(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, name := range settingNameRE.FindAllString(text, -1) {
		if _, ok := hardenedSettings[name]; ok && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// settingEdit is one changed line, for the diff: Old is empty for an insert.
type settingEdit struct{ Old, New string }

var (
	pbxObjectStartRE = regexp.MustCompile(`^\t\t([0-9A-Za-z_]+)(?: /\*.*\*/)? = \{\n$`)
	pbxSettingRE     = regexp.MustCompile(`^\t\t\t\t("?[A-Za-z0-9_]+(?:\[[^\]]*\])?"?) = `)
	pbxListMemberRE  = regexp.MustCompile(`^\t\t\t\t([0-9A-Za-z_]+)(?: /\*.*\*/)?,\n$`)
	pbxPlainValueRE  = regexp.MustCompile(`^[A-Za-z0-9_./]+$`)
)

// pbxObject is one multi-line object: its id and [start, end] line indexes.
type pbxObject struct {
	id         string
	start, end int
}

// pbxObjects indexes the multi-line objects of a project file by id.
func pbxObjects(lines []string) map[string]pbxObject {
	objs := map[string]pbxObject{}
	for i := 0; i < len(lines); i++ {
		m := pbxObjectStartRE.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			if lines[j] == "\t\t};\n" {
				objs[m[1]] = pbxObject{id: m[1], start: i, end: j}
				i = j
				break
			}
		}
	}
	return objs
}

// pbxField returns an object's top-level `key = value;` value, unquoted, or "".
func pbxField(lines []string, o pbxObject, key string) string {
	prefix := "\t\t\t" + key + " = "
	for _, l := range lines[o.start+1 : o.end] {
		if strings.HasPrefix(l, prefix) {
			v := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(l, prefix)), ";")
			if i := strings.Index(v, " /*"); i >= 0 {
				v = v[:i]
			}
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// appReleaseConfigs returns the Release build configurations of every
// application target, in file order.
func appReleaseConfigs(lines []string) []pbxObject {
	objs := pbxObjects(lines)
	var out []pbxObject
	for _, o := range objs {
		if pbxField(lines, o, "isa") != "PBXNativeTarget" ||
			pbxField(lines, o, "productType") != "com.apple.product-type.application" {
			continue
		}
		list, ok := objs[pbxField(lines, o, "buildConfigurationList")]
		if !ok {
			continue
		}
		for _, l := range lines[list.start+1 : list.end] {
			m := pbxListMemberRE.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			cfg, ok := objs[m[1]]
			if ok && strings.Contains(strings.ToLower(pbxField(lines, cfg, "name")), "release") {
				out = append(out, cfg)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out
}

// pbxValue formats a value the way Xcode writes it: quoted unless plain.
func pbxValue(v string) string {
	if pbxPlainValueRE.MatchString(v) {
		return v
	}
	return `"` + v + `"`
}

// applyBuildSettings sets each named setting to its hardened value in every
// application target's Release configurations: an existing line is rewritten,
// a missing one is inserted in key order. Nothing else in the file changes.
func applyBuildSettings(content string, names []string) (string, []settingEdit) {
	lines := strings.SplitAfter(content, "\n")
	replace := map[int]string{}
	insert := map[int][]string{} // before line index
	var edits []settingEdit
	for _, cfg := range appReleaseConfigs(lines) {
		begin, end := -1, -1
		for i := cfg.start + 1; i < cfg.end; i++ {
			if lines[i] == "\t\t\tbuildSettings = {\n" {
				begin = i
			} else if begin >= 0 && lines[i] == "\t\t\t};\n" {
				end = i
				break
			}
		}
		if begin < 0 || end < 0 {
			continue
		}
		for _, name := range names {
			want := "\t\t\t\t" + name + " = " + pbxValue(hardenedSettings[name]) + ";\n"
			at, found := end, false
			for i := begin + 1; i < end; i++ {
				m := pbxSettingRE.FindStringSubmatch(lines[i])
				if m == nil {
					continue
				}
				key := strings.Trim(m[1], `"`)
				if key == name {
					at, found = i, true
					break
				}
				if key > name && at == end {
					at = i
				}
			}
			switch {
			case found && lines[at] != want:
				replace[at] = want
				edits = append(edits, settingEdit{Old: lines[at], New: want})
			case !found:
				insert[at] = append(insert[at], want)
				edits = append(edits, settingEdit{New: want})
			}
		}
	}
	if len(edits) == 0 {
		return content, nil
	}
	var b strings.Builder
	for i, l := range lines {
		ins := insert[i]
		sort.Strings(ins)
		for _, s := range ins {
			b.WriteString(s)
		}
		if r, ok := replace[i]; ok {
			l = r
		}
		b.WriteString(l)
	}
	return b.String(), edits
}

// settingsDiff renders edits in the fixer's diff format.
func settingsDiff(p string, edits []settingEdit) string {
	var b strings.Builder
	for _, e := range edits {
		fmt.Fprintf(&b, "--- %s\n", p)
		if e.Old != "" {
			b.WriteString("- " + strings.TrimSuffix(e.Old, "\n") + "\n")
		}
		b.WriteString("+ " + strings.TrimSuffix(e.New, "\n") + "\n")
	}
	return b.String()
}

// checkPbxproj holds a project-file patch to exactly what applyBuildSettings
// would write for the hardening settings it touches: anything else -- another
// setting, another value, another configuration or target -- is rejected.
func checkPbxproj(p, original, patched string) *patchViolation {
	if path.Base(p) != "project.pbxproj" || original == patched {
		return nil
	}
	// Each added setting appears once per Release configuration it went into;
	// re-applying it once covers them all.
	var names []string
	seen := map[string]bool{}
	for _, l := range rawAddedLines(original, patched) {
		m := pbxSettingRE.FindStringSubmatch("\t\t\t\t" + strings.TrimSpace(l) + " ")
		if m == nil {
			continue
		}
		name := strings.Trim(m[1], `"`)
		if _, ok := hardenedSettings[name]; ok && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if expected, _ := applyBuildSettings(original, names); expected == patched {
		return nil
	}
	return &patchViolation{
		Rule: "pbxproj-edit",
		Detail: fmt.Sprintf("%s may change only hardening build settings in the app targets' Release "+
			"configurations, each to its fixed value; this patch changes something else.", p),
	}
}
