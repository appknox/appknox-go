package helper

import (
	"context"
	"strings"
	"testing"

	"github.com/appknox/appknox-go/agent"
)

// TestRun_SecondFindingInTheSameFileIsNotDropped is the regression test for
// mfva PR #18, where a crypto fix was lost to a PRNG fix in the same file.
func TestRun_SecondFindingInTheSameFileIsNotDropped(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app/A.java", "class A { int weak; int ecb; }\n")

	// Each fixer call rewrites one token, reading whatever is on disk now.
	d := autofixDeps{
		locate: func(context.Context, agent.Config, agent.Request) (string, error) {
			return "app/A.java", nil
		},
		agentFix: func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
			cur, err := readUnderRoot(req.RepoRoot, req.Path)
			if err != nil {
				return agent.FixResult{}, err
			}
			from, to := "weak", "secure"
			if strings.Contains(req.Finding, "ECB") {
				from, to = "ecb", "gcm"
			}
			return agent.FixResult{Changed: true, PatchedContent: strings.ReplaceAll(cur, from, to)}, nil
		},
	}

	s := fixSession{
		opts: AutofixOptions{FixMode: "agent", FileID: 24, DryRun: true},
		d:    d,
		root: root,
		work: newWorkingTree(root),
		targets: []analysisTarget{
			{AnalysisID: 1, Inputs: FindingInputs{
				Finding: "Weak PRNG", ClassHints: []string{"Lcom/x/A;"}, Remediation: "r"}},
			{AnalysisID: 2, Inputs: FindingInputs{
				Finding: "Insecure ECB", ClassHints: []string{"Lcom/x/A;"}, Remediation: "r"}},
		},
	}

	out, err := s.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Patches) == 0 {
		t.Fatal("expected at least one patch")
	}
	final := out.Patches[len(out.Patches)-1].Content
	if !strings.Contains(final, "secure") {
		t.Error("the first fix was clobbered by the second")
	}
	if !strings.Contains(final, "gcm") {
		t.Error("the second fix was dropped")
	}
}

// A dry run must leave the checkout exactly as it found it.
func TestWorkingTree_RestoreUndoesEveryEdit(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app/A.java", "original\n")
	w := newWorkingTree(root)

	if err := w.apply("app/A.java", "patched once\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.apply("app/A.java", "patched twice\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.restore(); err != nil {
		t.Fatal(err)
	}

	got, err := readUnderRoot(root, "app/A.java")
	if err != nil {
		t.Fatal(err)
	}
	if got != "original\n" {
		t.Fatalf("restore must undo every edit, got %q", got)
	}
}
