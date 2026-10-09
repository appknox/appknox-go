package helper

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/ghfetch"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/spf13/viper"
)

var (
	// Polling starts fast right after results are sent, when the next step is
	// due within seconds, and backs off to autofixPollInterval while the job
	// is queued or the model is working.
	autofixFastPoll     = 250 * time.Millisecond
	autofixPollInterval = 2 * time.Second
	autofixHardLimit    = 2 * time.Hour
	autofixSleep        = time.Sleep
)

// nextPollInterval backs off by half again each idle poll, up to the cap.
func nextPollInterval(current time.Duration) time.Duration {
	next := current + current/2
	if next > autofixPollInterval {
		return autofixPollInterval
	}
	return next
}

// AutofixOptions carries the flags for an autofix run.
type AutofixOptions struct {
	Repo          string // GitHub owner/name from CI (GITHUB_REPOSITORY)
	Ref           string // PR base / merge target; empty = the head branch
	HeadRef       string // feature branch this autofix belongs to (CI: GITHUB_HEAD_REF / GITHUB_REF)
	RepoPath      string // already-checked-out repo (CI: GITHUB_WORKSPACE)
	FileID        int    // Appknox file id; every finding at or above RiskThreshold is attempted
	RiskThreshold int    // minimum computed risk to attempt; runAutofix defaults an unset (<=0) value to 1
	GithubToken   string // GitHub token for the base fetch and branch push
	DryRun        bool   // fix but do not push a branch
}

// autofixDeps are the injectable collaborators (seams for cost-free tests).
type autofixDeps struct {
	client      *appknox.Client
	knoxiqReady func(ctx context.Context, fileID int) error
	baseTree    func(ctx context.Context, opts AutofixOptions) (root string, cleanup func(), err error)
	deliver     func(ctx context.Context, opts AutofixOptions, patches []filePatch, pr *appknox.AutofixPRText) (Delivery, error)
	report      func(ctx context.Context, opts AutofixOptions, requestID int, d Delivery, patches []filePatch) error
}

func defaultDeps() autofixDeps {
	return autofixDeps{
		client:      getClient(),
		knoxiqReady: checkKnoxIQReady,
		baseTree:    resolveBaseTree,
		deliver:     deliverBranch,
		report:      reportAutofixPR,
	}
}

// filePatch is one file's final fixed content.
type filePatch struct {
	Path    string
	Content string
	Diff    string
	Finding string
	// Formatting is cosmetic advice about the patch -- tabs in a space-indented
	// file, say. Reported on the run and never enforced: see formatting.go.
	Formatting string
}

// Outcome is the source-free result of a run.
type Outcome struct {
	Patches   []filePatch // per-file fixes that changed something
	BranchURL string      // GitHub PR URL after delivery
	CommitSHA string      // git commit SHA of the pushed branch
	Branch    string      // pushed branch name
	PRCreated bool        // true when GitHub opened a new PR this run

	// Findings holds one outcome line per KnoxIQ finding, as Appknox recorded it.
	Findings []appknox.AutofixOutcome
}

// ProcessAutofix runs the autofix flow and exits non-zero on error.
func ProcessAutofix(opts AutofixOptions) {
	out, err := runAutofix(context.Background(), opts, defaultDeps())
	printOutcomeLines(out.Findings)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	printOutcome(opts, out)
}

// runAutofix: KnoxIQ ready → start the job on Appknox → answer its tool calls
// on the base tree until it is done → deliver the patches as one PR.
func runAutofix(ctx context.Context, opts AutofixOptions, d autofixDeps) (Outcome, error) {
	if opts.FileID <= 0 {
		return Outcome{}, errors.New("autofix needs --file-id")
	}
	if viper.GetString("access-token") == "" {
		return Outcome{}, errors.New("autofix needs an Appknox access token (--access-token or APPKNOX_ACCESS_TOKEN)")
	}
	if d.client == nil {
		return Outcome{}, errors.New("autofix: missing Appknox client")
	}
	host, err := resolvedAPIHost()
	if err != nil {
		return Outcome{}, err
	}
	// File contents leave this machine as tool results; never in cleartext.
	if err := validateAPIEndpoint(host); err != nil {
		return Outcome{}, err
	}
	opts = applyCIDefaults(opts)
	// An unset RiskThreshold defaults to 1 (any non-Passed finding), not 0
	// (everything): on a real file most analyses are Passed, and attempting
	// them costs model calls for nothing.
	if opts.RiskThreshold <= 0 {
		opts.RiskThreshold = 1
	}
	if _, _, err := splitRepo(opts.Repo); err != nil {
		return Outcome{}, errors.New("autofix needs the CI repo (GITHUB_REPOSITORY) the PR is opened on")
	}
	if opts.Ref == "" {
		return Outcome{}, errNeedHeadRef
	}

	ctx, cancel := context.WithTimeout(ctx, autofixHardLimit)
	defer cancel()
	if d.knoxiqReady != nil {
		if err := d.knoxiqReady(ctx, opts.FileID); err != nil {
			return Outcome{}, err
		}
	}
	root, cleanup, err := d.baseTree(ctx, opts)
	if err != nil {
		return Outcome{}, err
	}
	defer cleanup()

	sess := newAutofixSession(root)
	// Leave the checkout as it was found. Safe because delivery builds its
	// payload from the patches in memory, and this runs after delivery.
	defer func() {
		if err := sess.work.restore(); err != nil {
			fmt.Printf("autofix: failed to restore the working tree to its original state: %v\n", err)
		}
	}()

	job, err := runJob(ctx, d.client, opts, sess)
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{Findings: job.Outcomes, Patches: sess.result()}
	if job.Status != appknox.AutofixStatusReady || len(out.Patches) == 0 || opts.DryRun {
		return out, nil
	}
	del, err := d.deliver(ctx, opts, out.Patches, job.PR)
	if err != nil {
		return out, err
	}
	out.BranchURL, out.CommitSHA, out.Branch, out.PRCreated = del.URL, del.CommitSHA, del.Branch, del.PRCreated
	if d.report != nil {
		if err := d.report(ctx, opts, job.ID, del, out.Patches); err != nil {
			return out, fmt.Errorf("pushed %s but failed to record on Appknox: %w", del.URL, err)
		}
	}
	return out, nil
}

// runJob starts the job, waits for Appknox's worker to take it, drives its
// findings on the checkout, and completes it: Ready (a PR to open) or
// Processed (nothing to deliver).
func runJob(ctx context.Context, client *appknox.Client, opts AutofixOptions, sess *autofixSession) (*appknox.AutofixRequest, error) {
	job, _, err := client.KnoxIQ.StartAutofix(ctx, opts.FileID, &appknox.AutofixStart{
		Repo:          opts.Repo,
		BaseRef:       opts.Ref,
		HeadRef:       opts.HeadRef,
		CommitSHA:     strings.TrimSpace(os.Getenv("GITHUB_SHA")),
		RiskThreshold: opts.RiskThreshold,
	})
	if err != nil {
		if isAutofixTimeout(ctx, err) {
			return nil, autofixTimeoutError(opts.FileID)
		}
		return nil, fmt.Errorf("autofix start failed: %w", err)
	}
	fmt.Println("\nAutofix status:")
	job, err = awaitWorker(ctx, client, opts.FileID, job)
	if err != nil {
		return nil, err
	}

	drv := newAutofixDriver(sess, func(ctx context.Context, req *appknox.AutofixTurnRequest) (*appknox.AutofixTurnResponse, error) {
		resp, _, err := client.KnoxIQ.AutofixTurn(ctx, opts.FileID, job.ID, req)
		return resp, err
	})
	outcomes, err := drv.run(ctx, job.Units)
	if err != nil {
		return nil, jobFailed(ctx, client, opts.FileID, job.ID, err)
	}
	done, _, err := client.KnoxIQ.CompleteAutofix(ctx, opts.FileID, job.ID, outcomes)
	if err != nil {
		return nil, jobFailed(ctx, client, opts.FileID, job.ID, err)
	}
	if len(done.Outcomes) == 0 {
		done.Outcomes = outcomes
	}
	fmt.Printf("  %s\n", done.Status)
	return done, nil
}

// awaitWorker polls the job until Appknox's worker has taken it and built its
// findings. The worker usually picks a job up within a second, so polling
// starts fast and backs off.
func awaitWorker(ctx context.Context, client *appknox.Client, fileID int, job *appknox.AutofixRequest) (*appknox.AutofixRequest, error) {
	last := ""
	interval := autofixFastPoll
	for {
		if job.Status != last {
			fmt.Printf("  %s\n", job.Status)
			last = job.Status
		}
		switch job.Status {
		case appknox.AutofixStatusProcessing:
			if job.Units != nil {
				fmt.Printf("  %d finding(s)\n", len(job.Units))
				return job, nil
			}
		case appknox.AutofixStatusPending:
		case appknox.AutofixStatusTimedOut:
			return nil, fmt.Errorf("autofix timed out for file %d: %s", fileID, firstNonEmpty(job.ErrorMessage, "no answer in time"))
		default:
			return nil, fmt.Errorf("autofix errored for file %d: %s", fileID, firstNonEmpty(job.ErrorMessage, "autofix failed"))
		}
		if ctx.Err() != nil {
			return nil, giveUp(client, fileID, job.ID)
		}
		autofixSleep(interval)
		interval = nextPollInterval(interval)
		next, _, err := client.KnoxIQ.GetAutofixRequest(ctx, fileID, job.ID)
		if err != nil {
			if isAutofixTimeout(ctx, err) {
				return nil, giveUp(client, fileID, job.ID)
			}
			return nil, fmt.Errorf("autofix status check failed: %w", err)
		}
		job = next
	}
}

// jobFailed reports why the run stopped; on a deadline it also tells Appknox,
// so the job does not sit in flight.
func jobFailed(ctx context.Context, client *appknox.Client, fileID, jobID int, err error) error {
	if isAutofixTimeout(ctx, err) {
		return giveUp(client, fileID, jobID)
	}
	return fmt.Errorf("autofix failed for file %d: %w", fileID, err)
}

// callSummary names a step's calls without their arguments, which may carry code.
func callSummary(calls []appknox.AutofixToolCall) string {
	counts := map[string]int{}
	var order []string
	for _, c := range calls {
		if counts[c.Name] == 0 {
			order = append(order, c.Name)
		}
		counts[c.Name]++
	}
	parts := make([]string, 0, len(order))
	for _, name := range order {
		parts = append(parts, fmt.Sprintf("%s×%d", name, counts[name]))
	}
	return strings.Join(parts, ", ")
}

// giveUp tells Appknox this run stopped waiting, so the worker frees itself.
func giveUp(client *appknox.Client, fileID, requestID int) error {
	_, _, _ = client.KnoxIQ.MarkAutofixRequestTimedOut(context.Background(), fileID, requestID)
	return autofixTimeoutError(fileID)
}

func isAutofixTimeout(ctx context.Context, err error) bool {
	return errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
}

func autofixTimeoutError(fileID int) error {
	return fmt.Errorf("autofix timed out for file %d after %s", fileID, autofixHardLimit)
}

// resolveBaseTree returns the tree fixes are made against: the base branch,
// because the PR is opened from it. A push run's checkout already is that
// branch. A pull_request run's checkout is the head (or a merge commit), so
// fixing it would carry the feature's other changes into the PR; the base is
// fetched from GitHub instead.
func resolveBaseTree(ctx context.Context, opts AutofixOptions) (string, func(), error) {
	if opts.RepoPath != "" && opts.Ref == opts.HeadRef {
		return opts.RepoPath, func() {}, nil
	}
	owner, name, err := splitRepo(opts.Repo)
	if err != nil {
		return "", nil, err
	}
	fmt.Printf("Fetching %s@%s to fix against the PR base\n", opts.Repo, opts.Ref)
	return ghfetch.FetchTarball(ctx, ghfetch.Config{
		Owner: owner, Repo: name, Ref: opts.Ref,
		Token:   firstNonEmpty(opts.GithubToken, os.Getenv("GITHUB_TOKEN")),
		APIBase: os.Getenv("GITHUB_API_URL"),
	})
}

// validateAPIEndpoint refuses plaintext HTTP to a non-loopback host: the
// token and the file contents answering tool calls would cross the network
// in cleartext.
func validateAPIEndpoint(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("autofix: invalid host: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("autofix: refusing plaintext http to non-loopback host %q — use https", u.Host)
}

// isLoopback reports whether host is localhost or a loopback IP.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// printOutcome renders the patches and the delivery.
func printOutcome(opts AutofixOptions, out Outcome) {
	if len(out.Patches) == 0 {
		fmt.Println("\nNo change produced.")
		return
	}
	for _, p := range out.Patches {
		fmt.Printf("\n=== %s ===\n", p.Path)
		if p.Formatting != "" {
			fmt.Printf("formatting (not enforced): %s\n", p.Formatting)
		}
		fmt.Println(p.Diff)
	}
	switch {
	case opts.DryRun:
		fmt.Printf("\n[dry-run] not pushing %d patched file(s).\n", len(out.Patches))
	case out.BranchURL != "":
		fmt.Printf("\n%s: %s\n", prAction(out.PRCreated), out.BranchURL)
		if out.CommitSHA != "" {
			fmt.Printf("commit: %s\n", out.CommitSHA)
		}
	}
}

func prAction(created bool) string {
	if created {
		return "Created PR"
	}
	return "Updated PR"
}

// repoComponentRE is GitHub's owner/repo charset — rejects "/", "?", spaces, etc.
// so a --repo value can never inject extra URL path/query segments (CWE-20).
var repoComponentRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// splitRepo parses and validates an "owner/name" repo spec.
func splitRepo(spec string) (string, string, error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 || !repoComponentRE.MatchString(parts[0]) || !repoComponentRE.MatchString(parts[1]) {
		return "", "", fmt.Errorf("invalid --repo %q, expected owner/name (letters, digits, . _ -)", spec)
	}
	return parts[0], parts[1], nil
}

// firstNonEmpty returns a if non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// workingTree tracks every file a run touches so the checkout can be put back
// afterwards, and so later findings see earlier fixes.
//
// Each finding fixes a file starting from whatever is on disk. Without this,
// two findings in one file would each be fixed against the ORIGINAL content and
// the second push would silently clobber the first -- which is exactly what
// happened on mfva PR #18, where a crypto fix was lost to a PRNG fix in the same
// file.
type workingTree struct {
	root     string
	original map[string]string // path -> content before we touched it
	// created holds paths that did not exist before this run touched them.
	// Their original is "" (a diff against nothing), and restore deletes
	// them rather than writing an empty file.
	created map[string]bool
	// createdDirs are the directories each created path needed, deepest
	// first, removed with it when they are empty again.
	createdDirs map[string][]string
}

func newWorkingTree(root string) *workingTree {
	return &workingTree{root: root, original: map[string]string{}, created: map[string]bool{},
		createdDirs: map[string][]string{}}
}

// track remembers a path's original content the first time the run touches
// it. A path that does not exist yet is recorded as created.
func (w *workingTree) track(path string) error {
	if _, seen := w.original[path]; seen {
		return nil
	}
	before, err := readUnderRoot(w.root, path)
	switch {
	case err == nil:
		w.original[path] = before
	case errors.Is(err, fs.ErrNotExist):
		dest, destErr := safeDest(w.root, path)
		if destErr != nil {
			return destErr
		}
		w.original[path] = ""
		w.created[path] = true
		w.createdDirs[path] = missingParents(dest)
	default:
		return err
	}
	return nil
}

// remove deletes a file this run created. The path stays recorded as
// created, so a later unit that creates it again, and the final restore, both
// still treat it as new.
func (w *workingTree) remove(path string) error {
	if !w.created[path] {
		return fmt.Errorf("refusing to delete %s: this run did not create it", path)
	}
	dest, err := safeDest(w.root, path)
	if err != nil {
		return err
	}
	if err := os.Remove(dest); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, dir := range w.createdDirs[path] {
		if os.Remove(dir) != nil {
			break // not empty (or gone): something else lives there
		}
	}
	return nil
}

// missingParents returns abs's ancestors that do not exist yet, deepest first.
func missingParents(abs string) []string {
	var dirs []string
	for dir := filepath.Dir(abs); filepath.Dir(dir) != dir; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
			break
		}
		dirs = append(dirs, dir)
	}
	return dirs
}

// restore puts every touched file back: created files are deleted, the rest
// rewritten.
func (w *workingTree) restore() error {
	for path, content := range w.original {
		if w.created[path] {
			if err := w.remove(path); err != nil {
				return err
			}
			continue
		}
		if err := applyPatch(w.root, path, content); err != nil {
			return err
		}
	}
	return nil
}

// lastPatchPerPath keeps one patch per path, preserving first-seen order so
// the pull request still reads in the order fixes were made.
//
// The kept filePatch's Content is always the LAST patch's: the final content
// already carries every earlier fix to that path via the working tree. When
// MORE THAN ONE patch touches a path, every patch's Finding is merged
// (deduplicated, first-seen order) and the Diff is recomputed from the path's
// ORIGINAL content -- before this run touched it -- to the FINAL content.
//
// original is the working tree's original -- the content read the first time
// each path was touched THIS run.
func lastPatchPerPath(patches []filePatch, original map[string]string) []filePatch {
	latest := make(map[string]filePatch, len(patches))
	findingSeen := map[string]map[string]bool{}
	findingOrder := map[string][]string{}
	var order []string
	for _, p := range patches {
		if _, seen := latest[p.Path]; !seen {
			order = append(order, p.Path)
			findingSeen[p.Path] = map[string]bool{}
		}
		latest[p.Path] = p
		if p.Finding != "" && !findingSeen[p.Path][p.Finding] {
			findingSeen[p.Path][p.Finding] = true
			findingOrder[p.Path] = append(findingOrder[p.Path], p.Finding)
		}
	}
	out := make([]filePatch, 0, len(order))
	for _, path := range order {
		out = append(out, collapsedPatch(latest[path], findingOrder[path], original[path]))
	}
	return out
}

// collapsedPatch merges names (every distinct Finding seen for p.Path) and
// recomputes the diff from before when more than one patch touched the path.
// A single-patch path is returned unchanged.
func collapsedPatch(p filePatch, names []string, before string) filePatch {
	if len(names) <= 1 {
		return p
	}
	p.Finding = strings.Join(names, "; ")
	if before != "" {
		if d := unifiedDiff(p.Path, before, p.Content); d != "" {
			p.Diff = d
		}
	}
	return p
}

// unifiedDiff renders a standard unified diff between two whole-file contents.
func unifiedDiff(path, before, after string) string {
	text, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(before), B: difflib.SplitLines(after),
		FromFile: path, ToFile: path, Context: 3,
	})
	if err != nil {
		return ""
	}
	return text
}
