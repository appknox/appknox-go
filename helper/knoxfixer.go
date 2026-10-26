package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/appknox/appknox-go/appknox"
)

// KnoxFixerOptions are the `appknox knoxfixer` flags.
type KnoxFixerOptions struct {
	FileID              int
	LikelihoodThreshold string // low | medium | high
	VerifyCmd           string
	AppRoot             string
}

const (
	knoxFixerMaxRun      = 60 * time.Minute
	knoxFixerPollWait    = 25
	knoxFixerPollBackoff = 2 * time.Second
)

// errSuperseded: another CLI run took over the job. Never push.
var errSuperseded = errors.New("superseded")

// ProcessKnoxFixer runs `appknox knoxfixer` and returns the process exit code.
// The CLI holds no prompt, model or LLM key: it locates files, sends small
// snippets, applies the edits Mycroft relays, and opens / updates the PR.
func ProcessKnoxFixer(opts KnoxFixerOptions) int {
	env, err := readKnoxFixerCIEnv(os.Getenv)
	if errors.Is(err, errKnoxFixerBranchSkip) {
		fmt.Println(errKnoxFixerBranchSkip.Error())
		return 0
	}
	if err != nil {
		PrintError(err)
		return 1
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		PrintError("GITHUB_TOKEN is not set. Pass it as env: GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }} " +
			"(the token stays on the runner and is never sent to Appknox)")
		return 1
	}
	fileID, err := resolveKnoxFixerFileID(opts.FileID, os.Getenv)
	if err != nil {
		PrintError(err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), knoxFixerMaxRun)
	defer cancel()
	cwd, _ := os.Getwd()
	root, err := gitToplevel(ctx, cwd)
	if err != nil {
		PrintError(err)
		return 1
	}

	client := getClient()
	job, err := client.KnoxFixer.CreateJob(ctx, &appknox.KnoxFixerCreateJobRequest{
		FileID:              fileID,
		RepoURL:             env.RepoURL,
		BaseBranch:          env.BaseBranch,
		CIProvider:          env.Provider,
		LikelihoodThreshold: opts.LikelihoodThreshold,
	})
	if err != nil {
		return reportCreateError(err)
	}
	if job.Attached {
		fmt.Printf("Attached to running knoxfixer job %d\n", job.JobID)
	} else {
		fmt.Printf("Knoxfixer job %d queued\n", job.JobID)
	}

	run := &knoxFixerRun{
		ctx: ctx, api: client.KnoxFixer, job: job, env: env, opts: opts, root: root,
		gh: newGitHubClient(env.APIURL, env.Repository, token),
	}
	return run.loop()
}

func reportCreateError(err error) int {
	var apiErr *appknox.KnoxFixerAPIError
	if errors.As(err, &apiErr) {
		if apiErr.Code == "branch_reserved" {
			fmt.Println("knoxfixer does not work on appknox-knoxfixer branch")
			return 0
		}
		PrintError("knoxfixer: " + apiErr.Detail)
		return 1
	}
	PrintError("knoxfixer: could not create job: ", err)
	return 1
}

type knoxFixerRun struct {
	ctx  context.Context
	api  *appknox.KnoxFixerService
	gh   *githubClient
	job  *appknox.KnoxFixerJob
	env  *knoxFixerCIEnv
	opts KnoxFixerOptions
	root string

	// state built while answering the plan
	git           *gitRunner
	cleanup       func()
	idx           *repoIndex
	head          string
	pr            *githubPR // PR being updated (open / reopened), nil → new PR
	located       map[string]string
	titles        map[string]string
	limits        appknox.KnoxFixerLimits
	conflictFiles []string
	lastSeq       int
}

type pollEvent struct {
	msg *appknox.KnoxFixerMessage
	err error
}

// poll is the only goroutine calling /next. It keeps polling during local
// work (that is the CLI's liveness signal) and hands every new message to
// the main flow through a channel, so nothing is lost while it is busy.
func (r *knoxFixerRun) poll(out chan<- pollEvent) {
	defer close(out)
	afterSeq := 0
	for r.ctx.Err() == nil {
		msg, err := r.api.Next(r.ctx, r.job.JobID, r.job.CLISession, afterSeq, knoxFixerPollWait)
		if err != nil {
			var apiErr *appknox.KnoxFixerAPIError
			if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
				out <- pollEvent{err: err}
				return
			}
			if r.ctx.Err() != nil {
				break
			}
			time.Sleep(knoxFixerPollBackoff) // transient network error: keep polling
			continue
		}
		if msg.Type == "wait" || msg.Seq <= afterSeq {
			continue
		}
		afterSeq = msg.Seq
		out <- pollEvent{msg: msg}
		if msg.Type == "done" || msg.Type == "failed" {
			return
		}
	}
	out <- pollEvent{err: context.DeadlineExceeded}
}

func (r *knoxFixerRun) loop() int {
	defer func() {
		if r.cleanup != nil {
			r.cleanup()
		}
	}()
	events := make(chan pollEvent, 32)
	go r.poll(events)

	for ev := range events {
		if ev.err != nil {
			return r.handlePollError(ev.err)
		}
		msg := ev.msg
		r.lastSeq = msg.Seq
		var err error
		switch msg.Type {
		case "plan":
			err = r.handlePlan(msg)
		case "need_context":
			err = r.handleNeedContext(msg)
		case "edits":
			var done bool
			done, err = r.handleEdits(msg)
			if err == nil && done {
				return 0
			}
		case "done":
			fmt.Println("knoxfixer: " + firstNonEmpty(msg.Payload.Message, "done"))
			return 0
		case "failed":
			PrintError(fmt.Sprintf("knoxfixer job %d failed: %s %s", r.job.JobID, msg.Payload.Reason, msg.Payload.Message))
			return 1
		}
		if err != nil {
			return r.fail(err)
		}
	}
	return r.fail(context.DeadlineExceeded)
}

func (r *knoxFixerRun) handlePollError(err error) int {
	var apiErr *appknox.KnoxFixerAPIError
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case "superseded":
			PrintError(fmt.Sprintf("another knoxfixer run took over job %d", r.job.JobID))
			return 1
		case "deadline_exceeded":
			PrintError("knoxfixer: DEADLINE_EXCEEDED (1 hour limit)")
			return 1
		}
		PrintError("knoxfixer: " + apiErr.Error())
		return 1
	}
	return r.fail(err)
}

// fail reports a CLI side failure (/abort) and returns the exit code.
func (r *knoxFixerRun) fail(err error) int {
	if errors.Is(err, errSuperseded) {
		PrintError(fmt.Sprintf("another knoxfixer run took over job %d", r.job.JobID))
		return 1
	}
	reason := "cli_error"
	var abortErr *knoxFixerAbort
	switch {
	case errors.As(err, &abortErr):
		reason = abortErr.reason
	case errors.Is(err, context.DeadlineExceeded):
		reason = "deadline_exceeded"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = r.api.Abort(ctx, r.job.JobID, r.job.CLISession, &appknox.KnoxFixerAbortRequest{
		InReplyToSeq: r.lastSeq, Reason: reason, Message: truncate(err.Error(), 400),
	})
	PrintError(fmt.Sprintf("knoxfixer job %d failed (%s): %v", r.job.JobID, reason, err))
	return 1
}

type knoxFixerAbort struct {
	reason string
	err    error
}

func (e *knoxFixerAbort) Error() string { return e.err.Error() }
func (e *knoxFixerAbort) Unwrap() error { return e.err }

func abortWith(reason string, err error) error { return &knoxFixerAbort{reason: reason, err: err} }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// --- plan ------------------------------------------------------------------------

func (r *knoxFixerRun) handlePlan(msg *appknox.KnoxFixerMessage) error {
	p := msg.Payload
	r.head = firstNonEmpty(p.HeadBranch, KnoxFixerBranchPrefix+r.env.BaseBranch)
	r.limits = p.Limits
	r.titles = map[string]string{}
	for _, f := range p.Findings {
		r.titles[f.Ref] = f.Title
	}
	if r.cleanup == nil {
		if err := r.prepareBranch(); err != nil {
			return err
		}
	}
	idx, err := buildRepoIndex(r.git.dir, r.opts.AppRoot)
	if err != nil {
		return err
	}
	r.idx = idx
	located, unresolved := locateFindings(idx, p.Findings)
	snippets, failed := buildSnippets(idx, located, p.Limits.SnippetLinesPerFinding)
	unresolved = append(unresolved, failed...)
	r.located = map[string]string{}
	for _, f := range located {
		r.located[f.Ref] = f.Path
	}

	req := &appknox.KnoxFixerContextRequest{
		InReplyToSeq: msg.Seq, UnresolvedRefs: unresolved, Snippets: snippets,
		ConflictFiles: r.conflictFiles,
	}
	if r.pr != nil {
		url := r.pr.HTMLURL
		req.PRURL = &url
	}
	fmt.Printf("knoxfixer: %d findings located, %d not found in the repository\n", len(located), len(unresolved))
	return r.sendContext(req)
}

func (r *knoxFixerRun) sendContext(req *appknox.KnoxFixerContextRequest) error {
	if req.Snippets == nil {
		req.Snippets = []appknox.KnoxFixerSnippet{}
	}
	err := r.api.SendContext(r.ctx, r.job.JobID, r.job.CLISession, req)
	var apiErr *appknox.KnoxFixerAPIError
	if errors.As(err, &apiErr) && apiErr.Code == "superseded" {
		return errSuperseded
	}
	return err
}

// prepareBranch picks the PR to update (GitHub is the only source of truth
// for PR state) and builds a worktree with base merged in.
func (r *knoxFixerRun) prepareBranch() error {
	ctx := r.ctx
	main := &gitRunner{dir: r.root}
	if err := main.fetchCommit(ctx, r.env.BaseBranch, r.env.BaseSHA); err != nil {
		return fmt.Errorf("could not fetch the CI commit: %w", err)
	}
	pr, openCount, err := r.gh.latestKnoxFixerPR(ctx, r.head, r.env.BaseBranch)
	if err != nil {
		return fmt.Errorf("could not list knoxfixer pull requests: %w", err)
	}
	if openCount > 1 {
		fmt.Printf("warning: %d open knoxfixer PRs for %s; using the newest (#%d)\n", openCount, r.env.BaseBranch, pr.Number)
	}

	existing := false
	switch {
	case pr != nil && pr.State == "open":
		existing = true
	case pr != nil && pr.MergedAt == nil: // closed without merge → reopen
		existing = r.reopen(pr)
	default: // merged or no PR: start fresh from base
		pr = nil
	}
	if !existing {
		pr = nil
		if exists, err := r.gh.branchExists(ctx, r.head); err != nil {
			return err
		} else if exists {
			if err := r.gh.deleteBranch(ctx, r.head); err != nil {
				return fmt.Errorf("could not delete stale branch %s: %w", r.head, err)
			}
		}
		wt, cleanup, err := main.addWorktree(ctx, r.env.BaseSHA)
		if err != nil {
			return err
		}
		r.git, r.cleanup = wt, cleanup
		return nil
	}

	r.pr = pr
	if err := main.fetchBranch(ctx, r.head); err != nil {
		return fmt.Errorf("could not fetch %s: %w", r.head, err)
	}
	wt, cleanup, err := main.addWorktree(ctx, "origin/"+r.head)
	if err != nil {
		return err
	}
	r.git, r.cleanup = wt, cleanup
	conflicts, err := wt.mergeTheirs(ctx, r.env.BaseSHA)
	if err != nil {
		return fmt.Errorf("could not merge %s into %s: %w", r.env.BaseBranch, r.head, err)
	}
	r.conflictFiles = conflicts
	if len(conflicts) > 0 {
		fmt.Printf("knoxfixer: %d files conflicted with %s; base code kept, their findings will be fixed again\n", len(conflicts), r.env.BaseBranch)
	}
	return nil
}

// reopen restores a deleted head branch at the PR's head commit and reopens
// the PR. false → caller falls back to a fresh branch + new PR.
func (r *knoxFixerRun) reopen(pr *githubPR) bool {
	ctx := r.ctx
	exists, err := r.gh.branchExists(ctx, r.head)
	if err != nil {
		return false
	}
	if !exists {
		if err := r.gh.createBranch(ctx, r.head, pr.Head.SHA); err != nil {
			return false
		}
	}
	if err := r.gh.reopenPR(ctx, pr.Number); err != nil {
		fmt.Printf("knoxfixer: could not reopen PR #%d (%v); opening a new PR\n", pr.Number, err)
		return false
	}
	fmt.Printf("knoxfixer: reopened PR #%d\n", pr.Number)
	return true
}

// --- need_context ----------------------------------------------------------------

func (r *knoxFixerRun) handleNeedContext(msg *appknox.KnoxFixerMessage) error {
	if r.idx == nil {
		return errors.New("need_context before plan")
	}
	snippets := buildNeedSnippets(r.idx, msg.Payload.Need, r.located, r.limits.ExtraContextLines)
	return r.sendContext(&appknox.KnoxFixerContextRequest{InReplyToSeq: msg.Seq, Snippets: snippets})
}

// --- edits → commit → push → PR --------------------------------------------------

func (r *knoxFixerRun) handleEdits(msg *appknox.KnoxFixerMessage) (bool, error) {
	if r.git == nil {
		return false, errors.New("edits before plan")
	}
	p := msg.Payload
	res, original, err := applyEdits(r.git.dir, p.Edits)
	if err != nil {
		return false, err
	}
	res, err = verifyAndRevert(r.ctx, r.git.dir, r.opts.VerifyCmd, p.Edits, res, original)
	if err != nil {
		return false, err
	}
	skipped := append(append([]appknox.KnoxFixerSkipped{}, p.Skipped...), res.Skipped...)
	if len(res.Files) == 0 {
		fmt.Println("knoxfixer: no edit could be applied; nothing to commit")
		return r.complete(msg.Seq, nil, "", nil, nil, skipped)
	}

	// Never push if another run owns the job now.
	if _, err := r.api.Next(r.ctx, r.job.JobID, r.job.CLISession, msg.Seq, 0); err != nil {
		var apiErr *appknox.KnoxFixerAPIError
		if errors.As(err, &apiErr) && apiErr.Code == "superseded" {
			return false, errSuperseded
		}
	}
	// From here commit + push run to the end even near the deadline (no
	// half-done commit), so use a context that outlives the job budget.
	finishCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	sha, err := r.git.commit(finishCtx, res.Files, firstNonEmpty(p.CommitMessage, p.PR.Title))
	if err != nil {
		return false, err
	}
	if err := r.git.push(finishCtx, r.head); err != nil {
		return false, abortWith(pushFailureReason(err), err)
	}

	var prURL string
	if r.pr != nil {
		if err := r.gh.updatePR(finishCtx, r.pr.Number, p.PR.Title, p.PR.Body); err != nil {
			fmt.Printf("warning: could not update PR #%d title/body: %v\n", r.pr.Number, err)
		}
		prURL = r.pr.HTMLURL
	} else {
		pr, err := r.gh.createPR(finishCtx, r.head, r.env.BaseBranch, p.PR.Title, p.PR.Body)
		if err != nil {
			if hint := prCreateHint(err); hint != "" {
				err = fmt.Errorf("%w (%s)", err, hint)
			}
			return false, abortWith("pr_create_failed", err)
		}
		prURL = pr.HTMLURL
	}

	var fixed []appknox.KnoxFixerFixed
	var refs []string
	for ref := range res.FilesByRef {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		fixed = append(fixed, appknox.KnoxFixerFixed{Ref: ref, FilesPatched: res.FilesByRef[ref]})
	}
	fmt.Printf("knoxfixer: %d findings fixed → %s\n", len(fixed), prURL)
	for _, s := range skipped {
		fmt.Printf("  skipped %s: %s\n", firstNonEmpty(s.Title, r.titles[s.Ref], s.Ref), s.Reason)
	}
	return r.complete(msg.Seq, &prURL, p.PR.Title, &sha, fixed, skipped)
}

func (r *knoxFixerRun) complete(seq int, prURL *string, title string, sha *string, fixed []appknox.KnoxFixerFixed, skipped []appknox.KnoxFixerSkipped) (bool, error) {
	if fixed == nil {
		fixed = []appknox.KnoxFixerFixed{}
	}
	for i := range skipped {
		skipped[i].Reason = truncate(skipped[i].Reason, 200)
		skipped[i].Title = ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	status, err := r.api.Complete(ctx, r.job.JobID, r.job.CLISession, &appknox.KnoxFixerCompleteRequest{
		InReplyToSeq: seq, PRURL: prURL, Title: title, CommitSHA: sha, Fixed: fixed, Skipped: skipped,
	})
	if err != nil {
		return false, err
	}
	if status != "" && status != "completed" && status != "running" {
		return false, fmt.Errorf("job ended with status %s", status)
	}
	if prURL != nil {
		fmt.Println("knoxfixer: PR " + *prURL)
	}
	return true, nil
}
