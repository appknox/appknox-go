package helper

import "testing"

// One autofix branch per feature branch: a later scan must reuse it, not open
// a second PR for the same work.
func TestAutofixBranchFor_isStablePerFeatureBranch(t *testing.T) {
	if got := autofixBranchFor("feature/payment"); got != "autofix-feature/payment" {
		t.Errorf("got %q, want autofix-feature/payment", got)
	}
	if autofixBranchFor("feature/payment") != autofixBranchFor("feature/payment") {
		t.Error("the same feature branch must always map to the same autofix branch")
	}
	if autofixBranchFor("feature/a") == autofixBranchFor("feature/b") {
		t.Error("different feature branches must not collide on one branch")
	}
}

func TestAutofixBranchFor_sanitisesRefUnsafeCharacters(t *testing.T) {
	got := autofixBranchFor("feature/pay ment~1")
	if got != "autofix-feature/pay-ment-1" {
		t.Errorf("got %q, want ref-safe characters only", got)
	}
}

func TestAutofixBranchFor_emptyWhenNoSourceBranch(t *testing.T) {
	if got := autofixBranchFor("  "); got != "" {
		t.Errorf("got %q, want empty so the caller can fall back", got)
	}
}

// A pull-request build must remediate the HEAD branch, not the merge ref.
func TestSourceBranch_prefersTheExplicitThenHeadRef(t *testing.T) {
	t.Setenv("GITHUB_HEAD_REF", "feature/from-pr")
	t.Setenv("GITHUB_REF_NAME", "refs/pull/7/merge")
	if got := SourceBranch(""); got != "feature/from-pr" {
		t.Errorf("got %q, want the PR head branch", got)
	}
	if got := SourceBranch("explicit/branch"); got != "explicit/branch" {
		t.Errorf("got %q, want the explicit value to win", got)
	}
}

func TestSourceBranch_fallsBackToRefNameOnPush(t *testing.T) {
	t.Setenv("GITHUB_HEAD_REF", "")
	t.Setenv("GITHUB_REF_NAME", "main")
	if got := SourceBranch(""); got != "main" {
		t.Errorf("got %q, want main", got)
	}
}
