package helper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	knoxFixerGitName  = "github-actions[bot]"
	knoxFixerGitEmail = "41898282+github-actions[bot]@users.noreply.github.com"
)

// gitRunner runs the git binary in one directory. Never force-pushes.
type gitRunner struct {
	dir string
}

type gitError struct {
	args   []string
	stderr string
	err    error
}

func (e *gitError) Error() string {
	return fmt.Sprintf("git %s: %v: %s", strings.Join(e.args, " "), e.err, strings.TrimSpace(e.stderr))
}

func (g *gitRunner) run(ctx context.Context, args ...string) (string, error) {
	full := append([]string{
		"-c", "user.name=" + knoxFixerGitName,
		"-c", "user.email=" + knoxFixerGitEmail,
		"-c", "core.hooksPath=" + os.DevNull,
	}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = g.dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), &gitError{args: args, stderr: stderr.String(), err: err}
	}
	return strings.TrimSpace(stdout.String()), nil
}

func gitToplevel(ctx context.Context, dir string) (string, error) {
	out, err := (&gitRunner{dir: dir}).run(ctx, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", errors.New("knoxfixer must run inside the git checkout of the repository")
	}
	return filepath.Clean(filepath.FromSlash(out)), nil
}

func (g *gitRunner) isShallow(ctx context.Context) bool {
	out, err := g.run(ctx, "rev-parse", "--is-shallow-repository")
	return err == nil && out == "true"
}

// fetchCommit makes sure sha (and the base branch tip) is available locally.
func (g *gitRunner) fetchCommit(ctx context.Context, branch, sha string) error {
	if _, err := g.run(ctx, "cat-file", "-e", sha+"^{commit}"); err == nil {
		return nil
	}
	if _, err := g.run(ctx, "fetch", "--no-tags", "origin", sha); err == nil {
		return nil
	}
	_, err := g.run(ctx, "fetch", "--no-tags", "origin", "+refs/heads/"+branch+":refs/remotes/origin/"+branch)
	if err != nil {
		return err
	}
	_, err = g.run(ctx, "cat-file", "-e", sha+"^{commit}")
	return err
}

// fetchBranch fetches origin/<branch> (full history if the clone is shallow,
// so merges find a merge base).
func (g *gitRunner) fetchBranch(ctx context.Context, branch string) error {
	refspec := "+refs/heads/" + branch + ":refs/remotes/origin/" + branch
	if g.isShallow(ctx) {
		if _, err := g.run(ctx, "fetch", "--no-tags", "--unshallow", "origin", refspec); err == nil {
			return nil
		}
	}
	_, err := g.run(ctx, "fetch", "--no-tags", "origin", refspec)
	return err
}

// addWorktree checks out ref in a separate temp worktree, so the CI
// workspace itself is never modified.
func (g *gitRunner) addWorktree(ctx context.Context, ref string) (*gitRunner, func(), error) {
	dir, err := os.MkdirTemp("", "appknox-knoxfixer-")
	if err != nil {
		return nil, nil, err
	}
	if _, err := g.run(ctx, "worktree", "add", "--detach", dir, ref); err != nil {
		os.RemoveAll(dir)
		return nil, nil, err
	}
	cleanup := func() {
		g.run(context.Background(), "worktree", "remove", "--force", dir)
		os.RemoveAll(dir)
	}
	return &gitRunner{dir: dir}, cleanup, nil
}

// mergeTheirs merges base into the PR branch keeping base's code on
// conflicting hunks (-X theirs). Modify/delete conflicts accept the
// deletion. Returns the files changed on both sides (their findings are
// treated as not fixed and get fixed again).
func (g *gitRunner) mergeTheirs(ctx context.Context, baseSHA string) ([]string, error) {
	mergeBase, err := g.run(ctx, "merge-base", "HEAD", baseSHA)
	if err != nil {
		return nil, err
	}
	if mergeBase == baseSHA {
		return nil, nil // base already merged
	}
	ours, err := g.changedFiles(ctx, mergeBase, "HEAD")
	if err != nil {
		return nil, err
	}
	theirs, err := g.changedFiles(ctx, mergeBase, baseSHA)
	if err != nil {
		return nil, err
	}
	conflicts := intersect(ours, theirs)

	_, mergeErr := g.run(ctx, "merge", "--no-edit", "--no-ff", "-X", "theirs", baseSHA,
		"-m", "Merge base into appknox-knoxfixer branch")
	if mergeErr != nil {
		unmerged, err := g.run(ctx, "diff", "--name-only", "--diff-filter=U")
		if err != nil || unmerged == "" {
			g.run(ctx, "merge", "--abort")
			return nil, mergeErr
		}
		for _, file := range strings.Split(unmerged, "\n") {
			file = strings.TrimSpace(file)
			if file == "" {
				continue
			}
			// Remaining conflicts are modify/delete: take base's side.
			if _, err := g.run(ctx, "checkout", "--theirs", "--", file); err != nil {
				if _, err := g.run(ctx, "rm", "--quiet", "--", file); err != nil {
					g.run(ctx, "merge", "--abort")
					return nil, err
				}
				continue
			}
			if _, err := g.run(ctx, "add", "--", file); err != nil {
				g.run(ctx, "merge", "--abort")
				return nil, err
			}
		}
		if _, err := g.run(ctx, "commit", "--no-edit"); err != nil {
			g.run(ctx, "merge", "--abort")
			return nil, err
		}
	}
	return conflicts, nil
}

func (g *gitRunner) changedFiles(ctx context.Context, from, to string) ([]string, error) {
	out, err := g.run(ctx, "diff", "--name-only", from, to)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

// commit stages only the patched files (never .appknox/ or anything else).
func (g *gitRunner) commit(ctx context.Context, files []string, message string) (string, error) {
	args := append([]string{"add", "--"}, files...)
	if _, err := g.run(ctx, args...); err != nil {
		return "", err
	}
	if _, err := g.run(ctx, "commit", "--no-verify", "-m", message); err != nil {
		return "", err
	}
	return g.run(ctx, "rev-parse", "HEAD")
}

// push is a normal (never forced) push of HEAD to refs/heads/<branch>.
func (g *gitRunner) push(ctx context.Context, branch string) error {
	_, err := g.run(ctx, "push", "--no-verify", "origin", "HEAD:refs/heads/"+branch)
	return err
}

// pushFailureReason maps git push stderr to the abort reason Mycroft expects.
func pushFailureReason(err error) string {
	var gerr *gitError
	if errors.As(err, &gerr) {
		msg := strings.ToLower(gerr.stderr)
		if strings.Contains(msg, "cannot lock ref") || strings.Contains(msg, "directory file conflict") ||
			strings.Contains(msg, "exists; cannot create") {
			return "branch_ref_conflict"
		}
	}
	return "push_failed"
}

func intersect(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	var out []string
	for _, x := range b {
		if set[x] {
			out = append(out, x)
			delete(set, x)
		}
	}
	return out
}
