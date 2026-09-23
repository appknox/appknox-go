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
// Every rule exists because its absence produced a measured defect. They are not
// general advice, and nothing here is speculative hardening.
//
// The evidence: 50 remediation plans from the KnoxIQ knowledge base were turned
// into compiling Java files carrying 2-3 occurrences of their vulnerability plus
// healthy surrounding code, then handed to blind fixers that saw only this prompt
// and the remediation -- no compiler, no repo, no knowledge of being measured.
// Each patch was scored with javac and adjudicated against the diff.
//
// The first version eliminated the vulnerability in all 50 and broke no build,
// but produced 9 overreach defects, 8 of which changed runtime behaviour while
// compiling cleanly -- the class no build gate can catch. One dropped a
// credential argument and silently bound an overload that sent a user session
// token instead of the provider key. One hand-wrote 380 lines of APK signature
// parsing from memory. Four described the defect in their own report and shipped
// it anyway.
//
// The rules below closed those. Re-measured on 20 items: same pass count, same
// zero build breaks, total diff 1153 -> ~435 lines. An unreviewable diff is a
// defect here, not a stylistic complaint -- it lands in a customer's repository.
//
// That evidence base is Java-only, one self-contained file at a time, scored
// with javac. Run against 20 real Android repositories on 2026-09-09, 8 of 20
// autofix branches did not compile -- and the corpus was manifests, resources,
// Gradle scripts, flavour matrices and cross-file imports, none of which the
// 50-file study contained. "Zero build breaks" was true inside its domain and
// said nothing about this one.
//
// Every one of those 8 was a multi-file remediation reaching a single-file
// fixer. KnoxIQ writes for a developer holding the whole repository: create
// res/xml/foo.xml then reference it; delete the trust manager then remove its
// use in LaunchWarmup.java; set debuggable in the manifest then set it again in
// build.gradle. Handed one file and a step it cannot perform, the fixer did one
// of two things, both fatal -- executed the destructive half alone, or
// improvised the change in whatever file it did have.
//
// SCOPE already told it to abstain. It abstained in none of the 8. So WHERE,
// ATOMIC and XML below do not add advice; they name the three shapes that
// produced the breaks, because "declare it out of scope" was too abstract to
// act on at the moment it mattered. The point is not to make the fixer capable
// of a multi-file fix -- no wording can -- but to make a reported gap, which is
// recoverable, beat a broken build, which is not.

// fixSystemPrompt is deliberately bare on this branch.
//
// Experiment (branch no-instructions): drop every fix rule -- SCOPE, WHERE,
// ATOMIC, XML, MINIMAL, COMPLETE, COMPILABLE, CONTAINED -- and let KnoxIQ's
// remediation alone drive the edit, to measure what the rules cost or buy
// against the rescan. The patch gate (verifyPatch) still runs unchanged.
const fixSystemPrompt = `You are a security fix assistant. You are given one file, a finding, and
KnoxIQ's remediation for it. Fix the finding in that file by following the
remediation.

Use the edit tool (str_replace) with a unique old_string. Edit only the file you
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

	// Before the remediation, because it constrains how the remediation can be
	// applied. Every line was read off the build files; the fixer sees one
	// source file and could not have derived any of it.
	if p := strings.TrimSpace(req.ProjectProfile); p != "" {
		fmt.Fprintf(&b, "This project, read from its build files:\n%s\n\n", p)
	}
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

	// Last, so it is the final thing read before the model acts. This is a
	// checked fact about the repository rather than a rule -- the rules were
	// already present on the attempt that produced the violation, and being
	// present was not enough.
	if v := strings.TrimSpace(req.PriorViolation); v != "" {
		fmt.Fprintf(&b, "\n\nA previous attempt at this file was rejected. This is the "+
			"reason, checked against the repository on disk:\n%s\n"+
			"That attempt has been discarded; you are starting from the original file. "+
			"Produce a fix that does not repeat it, or make no edit and report why.", v)
	}
	return b.String()
}
