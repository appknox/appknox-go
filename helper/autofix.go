package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
)

// AutofixOptions are the `appknox autofix` flags.
type AutofixOptions struct {
	FileID              int
	LikelihoodThreshold string // low | medium | high
	VerifyCmd           string
	AppRoot             string
}

const (
	autofixMaxRun      = 60 * time.Minute
	autofixPollWait    = 25
	autofixPollBackoff = 2 * time.Second
	// Repo listing sent once (paths only); the agent can list / search more.
	autofixMaxRepoFiles = 200000
)

// /complete: per-attempt timeout and the waits between retries (vars so
// tests can shorten them).
var (
	autofixCompleteTimeout = 60 * time.Second
	autofixCompleteBackoff = []time.Duration{5 * time.Second, 15 * time.Second}
)

// errSuperseded: another CLI run took over the job. Never push.
var errSuperseded = errors.New("superseded")

// printAutofixStatus is the only progress output `appknox autofix` writes
// to CI logs: Started / In progress / Completed, plus the PR link and any
// error. Everything else about the run (files touched, findings skipped,
// PR bookkeeping) stays internal.
func printAutofixStatus(status string) {
	fmt.Println("Autofix status: " + status)
}

// ProcessAutofix runs `appknox autofix` and returns the process exit code.
// The CLI holds no prompt, model or LLM key: it prepares the branch, runs the
// server-side fix agent's tools (list / search / read / edit / create /
// delete files, verify) in a worktree, then commits and opens / updates the PR.
func ProcessAutofix(opts AutofixOptions) int {
	env, err := readAutofixCIEnv(os.Getenv)
	if errors.Is(err, errAutofixBranchSkip) {
		fmt.Println(errAutofixBranchSkip.Error())
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
	fileID, err := resolveAutofixFileID(opts.FileID, os.Getenv)
	if err != nil {
		PrintError(err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), autofixMaxRun)
	defer cancel()
	cwd, _ := os.Getwd()
	root, err := gitToplevel(ctx, cwd)
	if err != nil {
		PrintError(err)
		return 1
	}

	client := getClient()
	job, err := client.Autofix.CreateJob(ctx, &appknox.AutofixCreateJobRequest{
		FileID:              fileID,
		RepoURL:             env.RepoURL,
		BaseBranch:          env.BaseBranch,
		CIProvider:          env.Provider,
		LikelihoodThreshold: opts.LikelihoodThreshold,
	})
	if err != nil {
		return reportCreateError(err)
	}
	run := &autofixRun{
		ctx: ctx, api: client.Autofix, job: job, env: env, opts: opts, root: root,
		gh: newGitHubClient(env.APIURL, env.Repository, token),
	}
	if job.Attached {
		run.inProgressPrinted = true
		printAutofixStatus("In progress")
	} else {
		printAutofixStatus("Started")
	}
	return run.loop()
}

func reportCreateError(err error) int {
	var apiErr *appknox.AutofixAPIError
	if errors.As(err, &apiErr) {
		if apiErr.Code == "branch_reserved" {
			fmt.Println("autofix does not work on appknox-autofix branch")
			return 0
		}
		PrintError("autofix: " + apiErr.Detail)
		return 1
	}
	PrintError("autofix: could not create job: ", err)
	return 1
}

type autofixRun struct {
	ctx  context.Context
	api  *appknox.AutofixService
	gh   *githubClient
	job  *appknox.AutofixJob
	env  *autofixCIEnv
	opts AutofixOptions
	root string

	// state built while answering `prepare`
	git           *gitRunner
	cleanup       func()
	tools         *toolRunner
	head          string
	pr            *githubPR // PR being updated (open / reopened), nil → new PR
	conflictFiles []string
	lastSeq       int

	inProgressPrinted bool // "Autofix status: In progress" printed once
}

type pollEvent struct {
	msg *appknox.AutofixMessage
	err error
}

// poll is the only goroutine calling /next. It keeps polling during local
// work (that is the CLI's liveness signal) and hands every new message to
// the main flow through a channel, so nothing is lost while it is busy.
func (r *autofixRun) poll(out chan<- pollEvent) {
	defer close(out)
	afterSeq := 0
	for r.ctx.Err() == nil {
		msg, err := r.api.Next(r.ctx, r.job.JobID, r.job.CLISession, afterSeq, autofixPollWait)
		if err != nil {
			var apiErr *appknox.AutofixAPIError
			if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
				out <- pollEvent{err: err}
				return
			}
			if r.ctx.Err() != nil {
				break
			}
			time.Sleep(autofixPollBackoff) // transient network error: keep polling
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

func (r *autofixRun) loop() int {
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
		case "prepare":
			err = r.handlePrepare(msg)
		case "tools":
			err = r.handleTools(msg)
		case "finish":
			var done bool
			done, err = r.handleFinish(msg)
			if err == nil && done {
				return 0
			}
		case "done":
			printAutofixStatus("Completed")
			return 0
		case "failed":
			PrintError(fmt.Sprintf("autofix job %d failed: %s %s", r.job.JobID, msg.Payload.Reason, msg.Payload.Message))
			return 1
		}
		if err != nil {
			return r.fail(err)
		}
	}
	return r.fail(context.DeadlineExceeded)
}

func (r *autofixRun) handlePollError(err error) int {
	var apiErr *appknox.AutofixAPIError
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case "superseded":
			PrintError(fmt.Sprintf("another autofix run took over job %d", r.job.JobID))
			return 1
		case "deadline_exceeded":
			PrintError("autofix: DEADLINE_EXCEEDED (1 hour limit)")
			return 1
		}
		PrintError("autofix: " + apiErr.Error())
		return 1
	}
	return r.fail(err)
}

// fail reports a CLI side failure (/abort) and returns the exit code.
func (r *autofixRun) fail(err error) int {
	if errors.Is(err, errSuperseded) {
		PrintError(fmt.Sprintf("another autofix run took over job %d", r.job.JobID))
		return 1
	}
	reason := "cli_error"
	var abortErr *autofixAbort
	switch {
	case errors.As(err, &abortErr):
		reason = abortErr.reason
	case errors.Is(err, context.DeadlineExceeded):
		reason = "deadline_exceeded"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = r.api.Abort(ctx, r.job.JobID, r.job.CLISession, &appknox.AutofixAbortRequest{
		InReplyToSeq: r.lastSeq, Reason: reason, Message: truncate(err.Error(), 400),
	})
	PrintError(fmt.Sprintf("autofix job %d failed (%s): %v", r.job.JobID, reason, err))
	return 1
}

type autofixAbort struct {
	reason string
	err    error
}

func (e *autofixAbort) Error() string { return e.err.Error() }
func (e *autofixAbort) Unwrap() error { return e.err }

func abortWith(reason string, err error) error { return &autofixAbort{reason: reason, err: err} }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// prepareBranch picks the PR to update (GitHub is the only source of truth
// for PR state) and builds a worktree with base merged in.
func (r *autofixRun) prepareBranch() error {
	ctx := r.ctx
	main := &gitRunner{dir: r.root}
	if err := main.fetchCommit(ctx, r.env.BaseBranch, r.env.BaseSHA); err != nil {
		return fmt.Errorf("could not fetch the CI commit: %w", err)
	}
	pr, _, err := r.gh.latestAutofixPR(ctx, r.head, r.env.BaseBranch)
	if err != nil {
		return fmt.Errorf("could not list autofix pull requests: %w", err)
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
	return nil
}

// reopen restores a deleted head branch at the PR's head commit and reopens
// the PR. false → caller falls back to a fresh branch + new PR.
func (r *autofixRun) reopen(pr *githubPR) bool {
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
		return false
	}
	return true
}

// --- prepare ---------------------------------------------------------------------

func (r *autofixRun) handlePrepare(msg *appknox.AutofixMessage) error {
	p := msg.Payload
	r.head = firstNonEmpty(p.HeadBranch, AutofixBranchPrefix+r.env.BaseBranch)
	if r.cleanup == nil {
		if err := r.prepareBranch(); err != nil {
			return err
		}
	}
	r.tools = newToolRunner(r.git.dir, r.opts.VerifyCmd)
	files := r.tools.repoFiles(autofixMaxRepoFiles)
	req := &appknox.AutofixContextRequest{
		InReplyToSeq:    msg.Seq,
		ConflictFiles:   append([]string{}, r.conflictFiles...),
		RepoFiles:       files,
		VerifyAvailable: r.opts.VerifyCmd != "",
	}
	if r.pr != nil {
		url := r.pr.HTMLURL
		req.PRURL = &url
	}
	if !r.inProgressPrinted {
		r.inProgressPrinted = true
		printAutofixStatus("In progress")
	}
	return r.sendContext(req)
}

func (r *autofixRun) sendContext(req *appknox.AutofixContextRequest) error {
	err := r.api.SendContext(r.ctx, r.job.JobID, r.job.CLISession, req)
	var apiErr *appknox.AutofixAPIError
	if errors.As(err, &apiErr) && apiErr.Code == "superseded" {
		return errSuperseded
	}
	return err
}

// --- tools ---------------------------------------------------------------------------

// handleTools runs the fix agent's tool calls in the worktree and sends back
// their results.
func (r *autofixRun) handleTools(msg *appknox.AutofixMessage) error {
	if r.tools == nil {
		return errors.New("tools before prepare")
	}
	results := r.tools.run(r.ctx, msg.Payload.Calls)
	err := r.api.SendToolResults(r.ctx, r.job.JobID, r.job.CLISession, &appknox.AutofixToolResultsRequest{
		InReplyToSeq: msg.Seq, Results: results,
	})
	var apiErr *appknox.AutofixAPIError
	if errors.As(err, &apiErr) && apiErr.Code == "superseded" {
		return errSuperseded
	}
	return err
}

// --- finish → commit → push → PR ------------------------------------------------------

func (r *autofixRun) handleFinish(msg *appknox.AutofixMessage) (bool, error) {
	if r.git == nil || r.tools == nil {
		return false, errors.New("finish before prepare")
	}
	p := msg.Payload
	files := r.tools.changedFiles()
	if len(p.Fixed) == 0 || len(files) == 0 || p.PR == nil {
		return r.complete(msg.Seq, nil, "", nil, nil, p.Skipped)
	}

	body := p.PR.Body
	if r.opts.VerifyCmd != "" {
		if ok, _ := runVerifyCommand(r.ctx, r.git.dir, r.opts.VerifyCmd); !ok {
			body = "> **Warning:** the configured verify command (`--verify-cmd`) failed on " +
				"this change. Check the CI log before merging.\n\n" + body
		}
	}

	// Never push if another run owns the job now.
	if _, err := r.api.Next(r.ctx, r.job.JobID, r.job.CLISession, msg.Seq, 0); err != nil {
		var apiErr *appknox.AutofixAPIError
		if errors.As(err, &apiErr) && apiErr.Code == "superseded" {
			return false, errSuperseded
		}
	}
	// From here commit + push run to the end even near the deadline (no
	// half-done commit), so use a context that outlives the job budget.
	finishCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	sha, err := r.git.commit(finishCtx, files, firstNonEmpty(p.CommitMessage, p.PR.Title))
	if err != nil {
		return false, err
	}
	if err := r.git.push(finishCtx, r.head); err != nil {
		return false, abortWith(pushFailureReason(err), err)
	}

	var prURL string
	if r.pr != nil {
		if err := r.gh.updatePR(finishCtx, r.pr.Number, p.PR.Title, body); err != nil {
			PrintError(fmt.Sprintf("autofix: could not update PR #%d title/body: %v", r.pr.Number, err))
		}
		prURL = r.pr.HTMLURL
	} else {
		pr, err := r.gh.createPR(finishCtx, r.head, r.env.BaseBranch, p.PR.Title, body)
		if err != nil {
			if hint := prCreateHint(err); hint != "" {
				err = fmt.Errorf("%w (%s)", err, hint)
			}
			return false, abortWith("pr_create_failed", err)
		}
		prURL = pr.HTMLURL
	}
	return r.complete(msg.Seq, &prURL, p.PR.Title, &sha, p.Fixed, p.Skipped)
}

func (r *autofixRun) complete(seq int, prURL *string, title string, sha *string, fixed []appknox.AutofixFixed, skipped []appknox.AutofixSkipped) (bool, error) {
	if fixed == nil {
		fixed = []appknox.AutofixFixed{}
	}
	out := make([]appknox.AutofixSkipped, 0, len(skipped))
	for _, s := range skipped {
		out = append(out, appknox.AutofixSkipped{Ref: s.Ref, Reason: truncate(s.Reason, 500)})
	}
	status, err := r.completeWithRetry(&appknox.AutofixCompleteRequest{
		InReplyToSeq: seq, PRURL: prURL, Title: title, CommitSHA: sha, Fixed: fixed, Skipped: out,
	})
	if err != nil {
		if prURL != nil {
			// The PR is pushed and open; only the bookkeeping call failed.
			// Don't fail the pipeline for that.
			PrintError(fmt.Sprintf("autofix: could not report the result to Appknox: %v", err))
			printAutofixStatus("Completed")
			fmt.Println("PR: " + *prURL)
			return true, nil
		}
		return false, abortWith("cli_error", fmt.Errorf("could not report the result to Appknox: %w", err))
	}
	if status != "" && status != "completed" && status != "running" {
		return false, fmt.Errorf("job ended with status %s", status)
	}
	printAutofixStatus("Completed")
	if prURL != nil {
		fmt.Println("PR: " + *prURL)
	}
	return true, nil
}

// completeWithRetry sends /complete, retrying network errors, timeouts and
// 5xx with backoff. A 4xx is final: the server rejected the reply.
func (r *autofixRun) completeWithRetry(req *appknox.AutofixCompleteRequest) (string, error) {
	var err error
	for attempt := 0; attempt < len(autofixCompleteBackoff)+1; attempt++ {
		if attempt > 0 {
			time.Sleep(autofixCompleteBackoff[attempt-1])
		}
		var status string
		ctx, cancel := context.WithTimeout(context.Background(), autofixCompleteTimeout)
		status, err = r.api.Complete(ctx, r.job.JobID, r.job.CLISession, req)
		cancel()
		if err == nil {
			return status, nil
		}
		var apiErr *appknox.AutofixAPIError
		if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
			return "", err
		}
	}
	return "", err
}
