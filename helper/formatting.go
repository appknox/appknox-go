package helper

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Formatting advice on a produced patch -- REPORTED, never enforced.
//
// This is deliberately not a gate check, and the distinction matters.
//
// Formatting does not break a build. Java, Kotlin and XML all compile
// regardless of indentation, so rejecting a patch over whitespace would trade
// a working security fix for cosmetics. That is the mistake this gate's
// history is built around: an earlier version rejected 75 patches and dropped
// 36, roughly half of them good, and the rule it earned was that rejecting a
// good patch is the expensive mistake.
//
// Silently reformatting would be worse than rejecting. Kotlin raw strings
// ("""...) preserve their whitespace, so normalising indentation inside one
// changes the VALUE of the string. A check that corrupts code in order to tidy
// it has no business running unattended.
//
// So this reports. A reviewer sees "this patch introduced tabs into a
// space-indented file" on the pull request and fixes it in a second, which is
// the right place for a cosmetic issue to be settled.

// formattingAdvice describes what a patch did to the file's formatting, or ""
// when it has nothing to say.
func formattingAdvice(path, original, patched string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".java", ".kt", ".xml":
	default:
		return ""
	}
	var notes []string
	if n := mixedIndentIntroduced(original, patched); n != "" {
		notes = append(notes, n)
	}
	if n := trailingSpaceIntroduced(original, patched); n > 0 {
		notes = append(notes, fmt.Sprintf("%d added line(s) end in trailing whitespace", n))
	}
	return strings.Join(notes, "; ")
}

// indentStyle reports whether a file indents with tabs or spaces.
//
// Returns "" when the file has no indentation or already uses both: a file
// with no established style cannot be departed from, and saying otherwise
// would be inventing a rule the repository never held.
func indentStyle(src string) string {
	tabs, spaces := 0, 0
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(line, "\t") {
			tabs++
		} else if strings.HasPrefix(line, "  ") {
			spaces++
		}
	}
	switch {
	case tabs > 0 && spaces == 0:
		return "tab"
	case spaces > 0 && tabs == 0:
		return "space"
	}
	return "" // none, or already mixed: no style to depart from
}

// mixedIndentIntroduced reports whether ADDED lines indent against the file's
// established style.
func mixedIndentIntroduced(original, patched string) string {
	style := indentStyle(original)
	if style == "" {
		return ""
	}
	for _, line := range addedLines(original, patched) {
		if style == "space" && strings.HasPrefix(line, "\t") {
			return "added lines use tabs in a space-indented file"
		}
		if style == "tab" && strings.HasPrefix(line, "  ") {
			return "added lines use spaces in a tab-indented file"
		}
	}
	return ""
}

// trailingSpaceIntroduced counts ADDED lines ending in whitespace.
func trailingSpaceIntroduced(original, patched string) int {
	n := 0
	for _, line := range addedLines(original, patched) {
		if line == "" || strings.TrimRight(line, " \t") == line {
			continue
		}
		n++
	}
	return n
}

// addedLines returns the lines of patched that do not appear in original.
//
// Line-level and set-based rather than a real diff: the question here is only
// "did the patch write this line", and a line the file already contained
// somewhere is not the fixer's doing. Same delta discipline as introduced() in
// verify_patch.go, which exists because judging the whole file blames the
// fixer for the repository it was handed.
func addedLines(original, patched string) []string {
	seen := make(map[string]bool)
	for _, line := range strings.Split(original, "\n") {
		seen[line] = true
	}
	var out []string
	for _, line := range strings.Split(patched, "\n") {
		if !seen[line] {
			out = append(out, line)
		}
	}
	return out
}
