package helper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const spaceIndented = "class A {\n    void f() {\n        log();\n    }\n}\n"

func TestFormattingAdvice_notesTabsInASpaceIndentedFile(t *testing.T) {
	patched := "class A {\n    void f() {\n\t\tlog();\n    }\n}\n"

	require.Contains(t, formattingAdvice("A.java", spaceIndented, patched),
		"tabs in a space-indented file")
}

func TestFormattingAdvice_notesSpacesInATabIndentedFile(t *testing.T) {
	original := "class A {\n\tvoid f() {\n\t\tlog();\n\t}\n}\n"
	patched := "class A {\n\tvoid f() {\n        log();\n\t}\n}\n"

	require.Contains(t, formattingAdvice("A.java", original, patched),
		"spaces in a tab-indented file")
}

func TestFormattingAdvice_countsTrailingWhitespaceOnAddedLines(t *testing.T) {
	patched := "class A {\n    void f() {\n        log();   \n        more();  \n    }\n}\n"

	require.Contains(t, formattingAdvice("A.java", spaceIndented, patched),
		"2 added line(s) end in trailing whitespace")
}

// Same delta discipline as the gate: a line the file already had is not the
// fixer's doing, even if it is untidy.
func TestFormattingAdvice_ignoresPreExistingUntidiness(t *testing.T) {
	original := "class A {\n    void f() {   \n        log();\n    }\n}\n"
	patched := original + "\n"

	require.Empty(t, formattingAdvice("A.java", original, patched))
}

// A file with no established style cannot be departed from, so claiming a
// departure would be inventing a rule the repository never held.
func TestFormattingAdvice_silentWhenTheFileIsAlreadyMixed(t *testing.T) {
	mixed := "class A {\n\tvoid f() {\n        log();\n\t}\n}\n"
	patched := "class A {\n\tvoid f() {\n        log();\n\t\tmore();\n\t}\n}\n"

	require.Empty(t, mixedIndentIntroduced(mixed, patched))
}

func TestIndentStyle(t *testing.T) {
	require.Equal(t, "space", indentStyle(spaceIndented))
	require.Equal(t, "tab", indentStyle("a {\n\tb\n}\n"))
	require.Empty(t, indentStyle("a {\n\tb\n  c\n}\n"), "mixed has no style")
	require.Empty(t, indentStyle("a\nb\n"), "no indentation at all")
}

// Only source files the fixer edits; a JSON or properties file has no style
// worth asserting here.
func TestFormattingAdvice_skipsUnrelatedExtensions(t *testing.T) {
	patched := "{\n\t\"a\": 1   \n}\n"
	require.Empty(t, formattingAdvice("data.json", "{\n    \"a\": 0\n}\n", patched))
}

// A clean patch must say nothing at all, or the advisory becomes noise that
// reviewers learn to skip.
func TestFormattingAdvice_silentOnACleanPatch(t *testing.T) {
	patched := "class A {\n    void f() {\n        log();\n        more();\n    }\n}\n"

	require.Empty(t, formattingAdvice("A.java", spaceIndented, patched))
}
