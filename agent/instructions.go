package agent

import (
	"fmt"
	"strings"
)

// The fix contract handed to the model, and the single source of truth for what
// "fixed" means here.
//
// Kept in one place, as appknox-mcp does for the MCP workflow, so the rules
// cannot drift between callers: whatever invokes the fixer gets the same
// definition of a correct fix, not a thinner one.
//
// Every rule below exists because its absence produced a real defect on
// appknox/mfva. They are not general advice.

// fixSystemPrompt states what a correct fix is.
//
// The two rules that matter most are MINIMAL and COMPLETE, and they pull in
// opposite directions on purpose: change nothing beyond what the remediation
// names, but change every place it applies.
const fixSystemPrompt = `You are a security fix assistant. You are given ONE file, a finding, and
KnoxIQ's remediation for it. Apply that remediation to that file.

MINIMAL - change only what the remediation names.
  Do NOT alter a method signature, argument list, overload, import, or exception
  surface unless the remediation explicitly calls for it. Dropping an argument
  can select a different overload and invalidate an existing catch clause, which
  does not compile. If the remediation says to change an algorithm string,
  change the algorithm string and nothing else.

COMPLETE - fix every occurrence the finding covers, not just the first.
  A finding may cover several call sites in one file. Read the whole file and
  fix all of them. One edit per site is expected; do not stop after one.

COMPILABLE - the file must still compile after your edit.
  Before finishing, re-read what you changed and check the surrounding code is
  still consistent with it: exceptions still thrown, imports present and used,
  types still matching, variables still in scope.

CONTAINED - touch nothing else.
  No reformatting, no renaming, no tidying, no changes to unrelated lines.
  Everything you are not fixing stays byte-for-byte identical.

If you cannot apply the remediation safely and completely, make NO edit and say
why. A missing fix is recoverable; a broken build, or a half-fix that reads as
done, is not.

Use the edit tool (str_replace) with a unique old_string. Edit ONLY the file you
are given.`

// fixUserPrompt renders the per-file instruction.
//
// developer_prompt is included when KnoxIQ supplied one: it is the guidance
// KnoxIQ writes for a human developer, and it is more specific than the generic
// remediation prose.
func fixUserPrompt(req FixRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target file (edit ONLY this): %s\n", req.Path)
	fmt.Fprintf(&b, "Finding: %s\n\n", req.Finding)
	fmt.Fprintf(&b, "Remediation:\n%s\n", req.Remediation)

	if strings.TrimSpace(req.DeveloperPrompt) != "" {
		fmt.Fprintf(&b, "\nKnoxIQ's guidance for the developer:\n%s\n", req.DeveloperPrompt)
	}
	if len(req.Criteria) > 0 {
		// The patch is machine-checked against these before it can be
		// delivered, so the model should aim at them rather than discover
		// afterwards that it missed one.
		b.WriteString("\nYour fix will be checked against these criteria:\n")
		for _, c := range req.Criteria {
			fmt.Fprintf(&b, "- %s\n", c)
		}
	}
	b.WriteString("\nRead the whole file first, then apply the fix. Use one edit " +
		"per occurrence; several occurrences need several edits.")
	return b.String()
}
