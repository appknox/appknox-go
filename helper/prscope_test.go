package helper

import (
	"context"
	"strings"
	"testing"

	"github.com/appknox/appknox-go/fixservice"
	"github.com/stretchr/testify/require"
)

// The stated requirement: apply suggested fixes ONLY to the files the developer
// modified in this pull request.
func TestScopeToPR_keepsOnlyChangedFiles(t *testing.T) {
	in, out := scopeToPR(
		[]string{"app/Main.java", "lib/Other.java"},
		[]string{"app/Main.java", "README.md"},
	)
	require.Equal(t, []string{"app/Main.java"}, in)
	require.Equal(t, []string{"lib/Other.java"}, out, "a file outside the PR must be advisory, not edited")
}

func TestScopeToPR_noOverlapFixesNothing(t *testing.T) {
	in, out := scopeToPR([]string{"lib/Other.java"}, []string{"README.md"})
	require.Empty(t, in)
	require.Equal(t, []string{"lib/Other.java"}, out)
}

func TestPRScoped_defaultsOnWithPRNumberAndOffWithout(t *testing.T) {
	require.True(t, AutofixOptions{PRNumber: 13}.prScoped(), "PR scope is the safe default")
	require.True(t, AutofixOptions{PRNumber: 13, Scope: "pr"}.prScoped())
	require.False(t, AutofixOptions{PRNumber: 13, Scope: "repo"}.prScoped(), "--scope repo must widen it")
	require.False(t, AutofixOptions{}.prScoped(), "no PR number means no PR scoping")
}

// The PR number belongs in the branch name so a reviewer can tell which PR a
// fix came from, and so two PRs fixing the same analysis cannot collide.
func TestPRBranch_carriesPRAndAnalysis(t *testing.T) {
	require.Equal(t, "bugfix/appknox-autofix-13-11829", prBranch(13, 11829, "app/Main.java"))
	require.Equal(t, "appknox-autofix/analysis-11829", prBranch(0, 11829, "app/Main.java"))
	require.True(t, strings.HasPrefix(prBranch(0, 0, "app/Main.java"), "appknox-autofix/fix-"))
}

// A reviewer must never read a tidy diff as proof the fix was checked.
func TestPRBody_saysWhenNothingWasVerified(t *testing.T) {
	body := prBody(FindingInputs{Finding: "Weak PRNG"}, []filePatch{{Path: "app/Main.java"}})
	require.Contains(t, body, "Not verified")
	require.Contains(t, body, "app/Main.java")

	checked := prBody(
		FindingInputs{Finding: "Weak PRNG", Criteria: []string{"No Math.random() remains"}},
		[]filePatch{{Path: "app/Main.java"}})
	require.Contains(t, checked, "No Math.random() remains")
	require.NotContains(t, checked, "Not verified")
}

// End to end through runAutofix: the out-of-PR file is located but not patched.
func TestRunAutofix_PRScope_skipsFilesOutsideThePR(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	d := deps(rel, fixservice.Result{Changed: true, PatchedContent: "fixed with SecureRandom\n"},
		oneClass("Insecure Random", "use SecureRandom"))
	d.prFiles = func(context.Context, AutofixOptions) ([]string, error) {
		return []string{"some/other/File.java"}, nil // the PR never touched rel
	}
	opts := appknoxOpts(root)
	opts.Repo, opts.PRNumber = "appknox/mfva", 13

	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Empty(t, out.Patches, "nothing outside the PR may be patched")
	require.Equal(t, []string{rel}, out.OutOfScope, "it should still be reported")
}

func TestRunAutofix_PRScope_fixesFilesInsideThePR(t *testing.T) {
	root, rel := repoWithFile(t, "orig\n")
	d := deps(rel, fixservice.Result{Changed: true, PatchedContent: "fixed with SecureRandom\n"},
		oneClass("Insecure Random", "use SecureRandom"))
	d.prFiles = func(context.Context, AutofixOptions) ([]string, error) {
		return []string{rel}, nil
	}
	opts := appknoxOpts(root)
	opts.Repo, opts.PRNumber = "appknox/mfva", 13

	out, err := runAutofix(context.Background(), opts, d)
	require.NoError(t, err)
	require.Len(t, out.Patches, 1)
	require.Empty(t, out.OutOfScope)
}
