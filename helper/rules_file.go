package helper

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Module ProGuard/R8 rules files are editable, additions only.
//
// KnoxIQ's remediation for Application Logs (mfva 17) strips android.util.Log
// from release builds with an -assumenosideeffects rule in
// app/proguard-rules.pro, and turning on minify (104) can need -keep or
// -dontwarn rules beside it. Adding such a rule narrows what R8 may remove or
// warn about; removing or rewriting one can strip a class the app needs at
// runtime, and a directive such as -include or -injars pulls in files from
// outside the rules the reviewer sees. So checkRulesFileEdit lets a patch add
// only the directives rulesDirectives lists, and never drop an existing rule.
//
// Only a module's own rules file is in bounds: proguard-rules.pro beside an
// editable module build script (editableBuildScript). The root one, a
// nested project's, and any other *.pro stay refused by buildFileRE.

// rulesFileName is the rules file every Android module template creates.
const rulesFileName = "proguard-rules.pro"

// rulesDirectives are the options a patch may add to a rules file.
var rulesDirectives = map[string]bool{
	"keep": true, "keepclassmembers": true, "keepclasseswithmembers": true,
	"keepnames": true, "keepclassmembernames": true, "keepclasseswithmembernames": true,
	"keepattributes": true, "dontwarn": true, "dontnote": true, "assumenosideeffects": true,
}

// rulesDirectiveRE finds every option on a line; ProGuard accepts several
// options on one line, so the first is not the only one that counts. Any
// non-word character may precede one: ProGuard treats } and , as delimiters.
var rulesDirectiveRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])-([A-Za-z]+)`)

// logStripRE is the one -assumenosideeffects target allowed: removing logging.
// Anything wider (class *, the app's own security checks) lets R8 delete calls
// the app depends on.
var logStripRE = regexp.MustCompile(`^\s+class\s+(android\.util\.Log|java\.io\.PrintStream)(\s|\{|$)`)

// Every -keep*, -dontwarn and -dontnote rule must name a real package or
// class that narrows it: blocklisting wildcard spellings (**, ***, **.*,
// ,allowshrinking) always misses one, and any of them switches shrinking or
// obfuscation off, or hides every missing-class warning.
var (
	// keepHeadRE parses a class specification up to its { : modifiers, an
	// optional annotation, access flags, the class keyword, the filter, and
	// an optional extends/implements.
	keepHeadRE = regexp.MustCompile(`^(,\w+)*\s+(@([A-Za-z_][\w$.]*)\s+)?((!?(public|final|abstract))\s+)*` +
		`(class|interface|enum|@interface)\s+([\w$.*,!?<>]+)` +
		`(\s+(extends|implements)\s+(@[A-Za-z_][\w$.]*\s+)?([\w$.*]+))?\s*$`)
	// dottedNameRE is a name with a literal first package segment:
	// com.appknox.**, android.os.Parcelable, but not *.** or ***.
	dottedNameRE = regexp.MustCompile(`^!?[A-Za-z_][\w$]*(\.[\w$*]+)+$`)
	// memberAnnotationRE is a dotted annotation in a member spec, which is
	// what narrows a member rule on every class (class *).
	memberAnnotationRE = regexp.MustCompile(`@[A-Za-z_][\w$]*\.[\w$.]+`)
)

// memberKeeping are the -keep* options that keep members, not classes.
var memberKeeping = map[string]bool{
	"keepclassmembers": true, "keepclassmembernames": true,
	"keepclasseswithmembers": true, "keepclasseswithmembernames": true,
}

// isModuleRulesFile reports, from the path alone, whether rel names a module's
// proguard-rules.pro. editableRulesFile adds the on-disk check.
func isModuleRulesFile(rel string) bool {
	rel = filepath.ToSlash(rel)
	if path.Base(rel) != rulesFileName || !strings.Contains(rel, "/") {
		return false
	}
	return isModuleBuildScript(path.Join(path.Dir(rel), "build.gradle"))
}

// editableRulesFile is isModuleRulesFile plus: an editable module build script
// sits beside it, so it belongs to a module rather than to a nested project's
// root or to no build at all.
func editableRulesFile(root, rel string) bool {
	if !isModuleRulesFile(rel) {
		return false
	}
	dir := path.Dir(filepath.ToSlash(rel))
	for _, name := range []string{"build.gradle", "build.gradle.kts"} {
		script := path.Join(dir, name)
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(script)))
		if err == nil && info.Mode().IsRegular() && editableBuildScript(root, script) {
			return true
		}
	}
	return false
}

// editableBuildFile reports whether a file buildFileRE matches may still be
// edited: a module build script or a module rules file.
func editableBuildFile(root, rel string) bool {
	return editableBuildScript(root, rel) || editableRulesFile(root, rel)
}

// checkRulesFileEdit refuses a rules-file patch that removes or rewrites an
// existing rule, adds an option rulesDirectives does not list or one that
// names no specific class, adds an @file include, or unbalances { }.
func checkRulesFileEdit(p, original, patched string) *patchViolation {
	if !isModuleRulesFile(p) {
		return nil
	}
	if gone := removedLines(ruleLines(original), ruleLines(patched)); len(gone) > 0 {
		return &patchViolation{
			Rule: "rules-file-removal",
			Detail: fmt.Sprintf("your edit to %s removes or changes the existing rule %q. "+
				"Only add rules; never remove or rewrite one.", p, strings.TrimSpace(gone[0])),
		}
	}
	have := multiset(ruleLines(original))
	var scan rulesScan
	for _, line := range ruleLines(patched) {
		k := strings.TrimSpace(line)
		if have[k] > 0 {
			have[k]--
		} else if bad := scan.judge(k); bad != "" {
			return rulesViolation(p, bad, k)
		}
		scan.advance(k)
		if scan.depth < 0 {
			return &patchViolation{
				Rule:   "rules-file-unbalanced",
				Detail: fmt.Sprintf("your edit to %s closes a { } block that was never opened.", p),
			}
		}
	}
	if scan.depth != 0 && blockDepth(ruleLines(original)) == 0 {
		return &patchViolation{
			Rule:   "rules-file-unbalanced",
			Detail: fmt.Sprintf("your edit to %s leaves a { } block unclosed.", p),
		}
	}
	return nil
}

func rulesViolation(p, bad, line string) *patchViolation {
	return &patchViolation{
		Rule: "rules-file-directive",
		Detail: fmt.Sprintf("your edit to %s adds %s in %q. Only -keep*, -dontwarn, -dontnote "+
			"and -assumenosideeffects on android.util.Log rules may be added, each naming a specific "+
			"package or class; if the remediation needs more, make no edit and report it.", p, bad, line),
	}
}

// rulesScan carries { } state across a rules file's lines, original and added.
type rulesScan struct {
	depth int
	// wildMembers is set inside a block whose class specification names no
	// specific class (class *): a member line added there must name a dotted
	// annotation, or the rule keeps every member of every class.
	wildMembers bool
}

// advance moves the scan past one line.
func (s *rulesScan) advance(line string) {
	before := s.depth
	s.depth += strings.Count(line, "{") - strings.Count(line, "}")
	if before == 0 && s.depth > 0 {
		s.wildMembers = wildBlockHead(line)
	}
	if s.depth <= 0 {
		s.wildMembers = false
	}
}

// judge reports why an added line may not be added, or "".
func (s *rulesScan) judge(line string) string {
	if bad := unsafeRuleChars(line); bad != "" {
		return bad
	}
	if s.depth > 0 {
		return s.judgeMember(line)
	}
	return judgeRule(line)
}

// judgeMember judges a line inside a class specification's { } block.
func (s *rulesScan) judgeMember(line string) string {
	if rulesDirectiveRE.MatchString(line) {
		return "an option inside a { } block"
	}
	if bad := atInclude(line, s.depth); bad != "" {
		return bad
	}
	if s.wildMembers && strings.Trim(line, "} ") != "" && !memberAnnotationRE.MatchString(line) {
		return "a member rule on every class that names no specific annotation"
	}
	return ""
}

// judgeRule judges a line outside every block: it must be options only, each
// listed and each narrowed to specific classes.
func judgeRule(line string) string {
	if !strings.HasPrefix(line, "-") {
		return "a line that is not an option (an @file include or a stray brace)"
	}
	ms := rulesDirectiveRE.FindAllStringSubmatchIndex(line, -1)
	if len(ms) > 1 && strings.ContainsAny(line, "{}") {
		// Which option a { belongs to is exactly what a second one blurs.
		return "more than one option on a line with a { } block"
	}
	for i, m := range ms {
		end := len(line)
		if i+1 < len(ms) {
			end = ms[i+1][0]
		}
		name := strings.ToLower(line[m[2]:m[3]])
		if bad := judgeOption(name, line[m[1]:end]); bad != "" {
			return bad
		}
	}
	return ""
}

// judgeOption judges one option and its arguments.
func judgeOption(name, args string) string {
	switch {
	case !rulesDirectives[name]:
		return "-" + name
	case name == "assumenosideeffects":
		if !logStripRE.MatchString(args) || strings.Contains(args, "@") {
			return "-assumenosideeffects on a class other than android.util.Log"
		}
	case name == "dontwarn" || name == "dontnote":
		if !specificFilters(args) {
			return "-" + name + " without a specific package"
		}
	case name == "keepattributes":
		if strings.ContainsAny(args, "{}@") {
			return "braces or @ after -keepattributes"
		}
	default:
		return judgeKeep(name, args)
	}
	return ""
}

// judgeKeep judges a -keep* option's class specification and any one-line
// member block.
func judgeKeep(name, args string) string {
	head, body, after, open, closed := splitBlock(args)
	if strings.TrimSpace(after) != "" || strings.Count(body, "{") > 0 {
		return "text after or inside a nested { } block"
	}
	m := keepHeadRE.FindStringSubmatch(head)
	if m == nil {
		return "an unrecognised -" + name + " class specification"
	}
	if keepHeadSpecific(m) {
		return ""
	}
	switch {
	case !memberKeeping[name]:
		return "-" + name + " on every class"
	case !open:
		return "-" + name + " on every class with no member specification"
	case closed && !memberAnnotationRE.MatchString(body):
		return "-" + name + " on every class that names no specific annotation"
	case !closed && strings.TrimSpace(body) != "" && !memberAnnotationRE.MatchString(body):
		return "-" + name + " on every class that names no specific annotation"
	}
	return ""
}

// splitBlock splits a class specification at its { and }.
func splitBlock(args string) (head, body, after string, open, closed bool) {
	i := strings.IndexByte(args, '{')
	if i < 0 {
		return args, "", "", false, false
	}
	head, rest := args[:i], args[i+1:]
	j := strings.IndexByte(rest, '}')
	if j < 0 {
		return head, rest, "", true, false
	}
	return head, rest[:j], rest[j+1:], true, true
}

// keepHeadSpecific reports whether a parsed class specification names a
// specific annotation, class filter or supertype.
func keepHeadSpecific(m []string) bool {
	if m[3] != "" && dottedNameRE.MatchString(m[3]) {
		return true
	}
	if specificList(m[8]) {
		return true
	}
	// Every class extends java.lang.Object: naming it narrows nothing.
	return m[12] != "" && m[12] != "java.lang.Object" && dottedNameRE.MatchString(m[12])
}

// wildBlockHead reports whether a line leaving a { } block open is a -keep*
// rule whose class specification names nothing specific. The block left open
// belongs to the line's LAST option, so that is the one judged.
func wildBlockHead(line string) bool {
	ms := rulesDirectiveRE.FindAllStringSubmatchIndex(line, -1)
	if len(ms) == 0 {
		return false
	}
	m := ms[len(ms)-1]
	if !strings.HasPrefix(strings.ToLower(line[m[2]:m[3]]), "keep") {
		return false
	}
	head, _, _, _, _ := splitBlock(line[m[1]:])
	hm := keepHeadRE.FindStringSubmatch(head)
	return hm == nil || !keepHeadSpecific(hm)
}

// specificFilters reports whether a -dontwarn/-dontnote argument is a
// non-empty comma list of dotted names.
func specificFilters(args string) bool {
	return strings.TrimSpace(args) != "" && specificList(args)
}

// specificList reports whether every comma-separated name is dotted and at
// least one is not negated: !com.a.B alone means every class but one.
func specificList(list string) bool {
	positive := false
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if !dottedNameRE.MatchString(f) {
			return false
		}
		positive = positive || !strings.HasPrefix(f, "!")
	}
	return positive
}

// unsafeRuleChars refuses what would let ProGuard read a line differently from
// this gate: quotes (a quoted word hides # and braces), control characters
// and any non-ASCII rune (Java counts more runes as whitespace than Go does).
func unsafeRuleChars(line string) string {
	for _, r := range line {
		switch {
		case r == '"' || r == '\'':
			return "a quote"
		case r == '\t':
		case r < 0x20 || r > 0x7e:
			return fmt.Sprintf("the character %U", r)
		}
	}
	return ""
}

// atInclude reports an @file include inside a member line: an @ once the line
// has closed every block it was in. A } with no block open is refused too.
func atInclude(line string, depth int) string {
	for _, r := range line {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
		case '@':
			if depth <= 0 {
				return "an @file include"
			}
		}
		if depth < 0 {
			return "an unopened }"
		}
	}
	return ""
}

// ruleLines returns src's lines with # comments stripped, blank ones dropped.
func ruleLines(src string) []string {
	// A bare CR ends a line for ProGuard's reader, so it does here too.
	src = strings.ReplaceAll(strings.ReplaceAll(src, "\r\n", "\n"), "\r", "\n")
	var out []string
	for _, line := range strings.Split(src, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// removedLines returns the lines of before that after no longer has, counted
// as a multiset.
func removedLines(before, after []string) []string {
	have := multiset(after)
	var out []string
	for _, line := range before {
		k := strings.TrimSpace(line)
		if have[k] > 0 {
			have[k]--
			continue
		}
		out = append(out, line)
	}
	return out
}

// multiset counts lines by their trimmed text.
func multiset(lines []string) map[string]int {
	m := map[string]int{}
	for _, line := range lines {
		m[strings.TrimSpace(line)]++
	}
	return m
}

// blockDepth is the net { } nesting across lines.
func blockDepth(lines []string) int {
	depth := 0
	for _, line := range lines {
		depth += strings.Count(line, "{") - strings.Count(line, "}")
	}
	return depth
}
