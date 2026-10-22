package helper

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// fixCall is what one fix turn was asked to do, recorded by test stubs.
type fixCall struct {
	Path  string
	TC    targetContext
	Prior *patchViolation
}

// gateSession builds a fixSession whose fixer returns the given patched
// contents in order, one per attempt, recording what it was told.
func gateSession(t *testing.T, root string, patches []string) (fixSession, *[]fixCall) {
	t.Helper()
	var seen []fixCall
	n := 0
	d := autofixDeps{
		fix: func(_ context.Context, fixPath string, fixTC targetContext, fixPrior *patchViolation) (fixResult, error) {
			seen = append(seen, fixCall{Path: fixPath, TC: fixTC, Prior: fixPrior})
			content := patches[len(patches)-1]
			if n < len(patches) {
				content = patches[n]
			}
			n++
			return fixResult{Changed: true, PatchedContent: content}, nil
		},
	}
	s := fixSession{
		opts: AutofixOptions{},
		d:    d,
		root: root,
	}
	return s, &seen
}

// writeSource puts original content on disk, which is where produceFixFor reads
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

	res, _, err := s.produceFixFor(context.Background(), "app/A.java", targetContext{})
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

	res, _, err := s.produceFixFor(context.Background(), "app/A.java", targetContext{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.PatchedContent != "class A { void f() { g(); } }\n" {
		t.Fatalf("second attempt should be kept, got %q", res.PatchedContent)
	}
	if len(*seen) != 2 {
		t.Fatalf("want exactly one retry, got %d attempts", len(*seen))
	}
	if (*seen)[0].Prior != nil {
		t.Error("first attempt must not carry a prior violation")
	}
	if (*seen)[1].Prior == nil {
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

	res, _, err := s.produceFixFor(context.Background(), "app/A.java", targetContext{})
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

	res, _, err := s.produceFixFor(context.Background(), "build.gradle", targetContext{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("build scripts are out of scope and must never be delivered")
	}
}

func TestProduceFix_AbstentionIsNotGated(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app/A.java", "class A { }\n")
	s := fixSession{
		opts: AutofixOptions{},
		root: root,
		d: autofixDeps{
			fix: func(context.Context, string, targetContext, *patchViolation) (fixResult, error) {
				return fixResult{Changed: false}, nil
			},
		},
	}

	res, _, err := s.produceFixFor(context.Background(), "app/A.java", targetContext{})
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

	res, _, err := s.produceFixFor(context.Background(), "app/Missing.java", targetContext{})
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
