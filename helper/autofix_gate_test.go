package helper

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/appknox/appknox-go/agent"
)

// gateSession builds a fixSession in agent mode whose fixer returns the given
// patched contents in order, one per attempt, recording what it was told.
func gateSession(t *testing.T, root string, patches []string) (fixSession, *[]agent.FixRequest) {
	t.Helper()
	var seen []agent.FixRequest
	n := 0
	d := autofixDeps{
		agentFix: func(_ context.Context, _ agent.Config, req agent.FixRequest) (agent.FixResult, error) {
			seen = append(seen, req)
			content := patches[len(patches)-1]
			if n < len(patches) {
				content = patches[n]
			}
			n++
			return agent.FixResult{Changed: true, PatchedContent: content}, nil
		},
	}
	s := fixSession{
		opts:    AutofixOptions{FixMode: "agent"},
		d:       d,
		root:    root,
		profile: "Gradle (AGP 8), compileSdk 34",
	}
	return s, &seen
}

// writeSource puts original content on disk, which is where produceFix reads
// the pre-patch file from.
func writeSource(t *testing.T, root, rel, content string) {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProduceFix_CleanPatchPassesFirstTime(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app/A.java", "class A { void f() {} }\n")
	s, seen := gateSession(t, root, []string{"class A { void f() { g(); } }\n"})

	res, err := s.produceFix(context.Background(), "app/A.java", oneClass("f", "r"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("clean patch should be kept")
	}
	if len(*seen) != 1 {
		t.Fatalf("clean patch must not retry, got %d attempts", len(*seen))
	}
}

func TestProduceFix_RetriesOnceThenKeepsTheFixedPatch(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app/A.java", "class A { void f() {} }\n")
	// First attempt drops a closing brace; the second is balanced.
	s, seen := gateSession(t, root, []string{
		"class A { void f() { g(); }\n",
		"class A { void f() { g(); } }\n",
	})

	res, err := s.produceFix(context.Background(), "app/A.java", oneClass("f", "r"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.PatchedContent != "class A { void f() { g(); } }\n" {
		t.Fatalf("second attempt should be kept, got %q", res.PatchedContent)
	}
	if len(*seen) != 2 {
		t.Fatalf("want exactly one retry, got %d attempts", len(*seen))
	}
	if (*seen)[0].PriorViolation != "" {
		t.Error("first attempt must not carry a prior violation")
	}
	if (*seen)[1].PriorViolation == "" {
		t.Error("retry must be told the fact the first attempt got wrong")
	}
}

func TestProduceFix_AbandonsFileWhenRetryAlsoViolates(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app/A.java", "class A { void f() {} }\n")
	// Both attempts are unbalanced, so the patch is discarded, not shipped.
	s, seen := gateSession(t, root, []string{
		"class A { void f() { g(); }\n",
		"class A { void f() { h(); }\n",
	})

	res, err := s.produceFix(context.Background(), "app/A.java", oneClass("f", "r"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || res.PatchedContent != "" {
		t.Fatalf("a twice-rejected patch must be discarded, got %q", res.PatchedContent)
	}
	if len(*seen) != 2 {
		t.Fatalf("want one retry then abandon, got %d attempts", len(*seen))
	}
}

func TestProduceFix_BuildScriptIsNeverDelivered(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "build.gradle", "android { }\n")
	s, _ := gateSession(t, root, []string{"android { buildConfig true }\n"})

	res, err := s.produceFix(context.Background(), "build.gradle", oneClass("f", "r"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("build scripts are out of scope and must never be delivered")
	}
}

func TestProduceFix_PassesProjectProfileToTheFixer(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app/A.java", "class A { }\n")
	s, seen := gateSession(t, root, []string{"class A { int x; }\n"})

	if _, err := s.produceFix(context.Background(), "app/A.java", oneClass("f", "r")); err != nil {
		t.Fatal(err)
	}
	if len(*seen) == 0 || (*seen)[0].ProjectProfile != "Gradle (AGP 8), compileSdk 34" {
		t.Error("the fixer must be told what kind of project this is")
	}
}

func TestProduceFix_AbstentionIsNotGated(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app/A.java", "class A { }\n")
	s := fixSession{
		opts: AutofixOptions{FixMode: "agent"},
		root: root,
		d: autofixDeps{
			agentFix: func(context.Context, agent.Config, agent.FixRequest) (agent.FixResult, error) {
				return agent.FixResult{Changed: false}, nil
			},
		},
	}

	res, err := s.produceFix(context.Background(), "app/A.java", oneClass("f", "r"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("an abstention is already the safe outcome")
	}
}

// A file the gate cannot read has no computable delta, and a check that cannot
// be computed must not reject.
func TestProduceFix_UnreadableOriginalDoesNotReject(t *testing.T) {
	root := t.TempDir()
	s, seen := gateSession(t, root, []string{"class A { void f() { }\n"})

	res, err := s.produceFix(context.Background(), "app/Missing.java", oneClass("f", "r"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("an uncomputable check must not discard the patch")
	}
	if len(*seen) != 1 {
		t.Fatalf("no retry when the gate could not run, got %d attempts", len(*seen))
	}
}
