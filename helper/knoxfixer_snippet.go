package helper

import (
	"regexp"
	"sort"
	"strings"

	"github.com/appknox/appknox-go/appknox"
)

// Only small line ranges ever leave the runner: ±60 lines per finding
// (limit from the plan), overlapping / adjacent ranges of one file merged
// into one snippet with all their refs, secrets masked.

// MaskToken replaces secret values in snippets (KnoxFixer refuses edits
// that touch it, so a masked secret is never rewritten).
const MaskToken = "__APPKNOX_MASKED__"

const maxSnippetLineChars = 2000

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{30,}`),
	regexp.MustCompile(`xox[abpr]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`),
	// key = "value" / key: 'value' / <string name="api_key">value</string>
	regexp.MustCompile(`(?i)((?:api[_-]?key|secret|token|passw(?:or)?d|pwd|private[_-]?key|client[_-]?secret|access[_-]?key)[A-Za-z0-9_\-]*["']?\s*(?:=|:|=>)\s*["'])([^"'\s]{6,})(["'])`),
	regexp.MustCompile(`(?i)(<string\s+name="[^"]*(?:key|secret|token|password)[^"]*"\s*>)([^<]{6,})(</string>)`),
}

var privateKeyBlockRe = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)

func maskSecrets(text string) string {
	text = privateKeyBlockRe.ReplaceAllStringFunc(text, func(block string) string {
		return strings.Repeat(MaskToken+"\n", strings.Count(block, "\n")) + MaskToken
	})
	for _, re := range secretPatterns {
		if re.NumSubexp() == 3 {
			text = re.ReplaceAllString(text, "${1}"+MaskToken+"${3}")
		} else {
			text = re.ReplaceAllString(text, MaskToken)
		}
	}
	return text
}

type lineRange struct {
	start, end int
	refs       []string
}

// sliceLines returns lines [start, end] (1-based, inclusive) keeping the
// original line endings.
func sliceLines(content string, start, end int) string {
	lines := strings.SplitAfter(content, "\n")
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start > end {
		return ""
	}
	return strings.Join(lines[start-1:end], "")
}

func lineCount(content string) int {
	if content == "" {
		return 1
	}
	n := strings.Count(content, "\n")
	if !strings.HasSuffix(content, "\n") {
		n++
	}
	return n
}

func clampRange(anchor, total, size int) (int, int) {
	half := size / 2
	start := anchor - half
	if start < 1 {
		start = 1
	}
	end := start + size - 1
	if end > total {
		end = total
		start = end - size + 1
		if start < 1 {
			start = 1
		}
	}
	return start, end
}

// buildSnippets: one ±limit/2 range per located finding, merged per file.
func buildSnippets(idx *repoIndex, located []locatedFinding, perFinding int) ([]appknox.KnoxFixerSnippet, []string) {
	if perFinding <= 0 {
		perFinding = 120
	}
	byPath := map[string][]lineRange{}
	contents := map[string]string{}
	var failed []string
	for _, f := range located {
		content, ok := contents[f.Path]
		if !ok {
			var err error
			content, err = idx.read(f.Path)
			if err != nil {
				failed = append(failed, f.Ref)
				continue
			}
			contents[f.Path] = content
		}
		start, end := clampRange(f.Line, lineCount(content), perFinding)
		byPath[f.Path] = append(byPath[f.Path], lineRange{start: start, end: end, refs: []string{f.Ref}})
	}
	var paths []string
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var snippets []appknox.KnoxFixerSnippet
	for _, p := range paths {
		for _, r := range mergeRanges(byPath[p]) {
			snippets = append(snippets, appknox.KnoxFixerSnippet{
				Refs: r.refs, Path: p, StartLine: r.start, EndLine: r.end,
				Content: maskSecrets(sliceLines(contents[p], r.start, r.end)),
			})
		}
	}
	return snippets, failed
}

// mergeRanges merges overlapping or touching ranges; a merged range of n
// refs is at most n × the per-finding limit, so merging never breaks it.
func mergeRanges(ranges []lineRange) []lineRange {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	var out []lineRange
	for _, r := range ranges {
		if n := len(out); n > 0 && r.start <= out[n-1].end+1 {
			if r.end > out[n-1].end {
				out[n-1].end = r.end
			}
			out[n-1].refs = append(out[n-1].refs, r.refs...)
			continue
		}
		out = append(out, lineRange{start: r.start, end: r.end, refs: append([]string{}, r.refs...)})
	}
	return out
}

// buildNeedSnippets answers need_context: per ref, the asked ranges of the
// same file (clipped to the extra-context limit), one snippet per ref.
func buildNeedSnippets(idx *repoIndex, need []appknox.KnoxFixerNeed, located map[string]string, extra int) []appknox.KnoxFixerSnippet {
	if extra <= 0 {
		extra = 200
	}
	byRef := map[string][]appknox.KnoxFixerNeed{}
	var refs []string
	for _, n := range need {
		if located[n.Ref] != n.Path { // only the finding's own file
			continue
		}
		if _, ok := byRef[n.Ref]; !ok {
			refs = append(refs, n.Ref)
		}
		byRef[n.Ref] = append(byRef[n.Ref], n)
	}
	var snippets []appknox.KnoxFixerSnippet
	for _, ref := range refs {
		ranges := byRef[ref]
		content, err := idx.read(ranges[0].Path)
		if err != nil {
			continue
		}
		start, end := ranges[0].StartLine, ranges[0].EndLine
		for _, r := range ranges[1:] {
			if r.StartLine < start {
				start = r.StartLine
			}
			if r.EndLine > end {
				end = r.EndLine
			}
		}
		if total := lineCount(content); end > total {
			end = total
		}
		if start < 1 {
			start = 1
		}
		if end-start+1 > extra {
			end = start + extra - 1
		}
		if end < start {
			continue
		}
		snippets = append(snippets, appknox.KnoxFixerSnippet{
			Refs: []string{ref}, Path: ranges[0].Path, StartLine: start, EndLine: end,
			Content: maskSecrets(sliceLines(content, start, end)),
		})
	}
	return snippets
}
