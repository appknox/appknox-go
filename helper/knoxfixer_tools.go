package helper

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/appknox/appknox-go/appknox"
)

// The fix agent (on the server) asks for these tools; the CLI runs them in
// the knoxfixer worktree of the customer's repository. Files are read in full
// when asked (they only pass through the server, never stored there); secret
// values are replaced by placeholders before anything leaves the runner and
// restored when the agent writes them back.

const (
	maxListedFiles   = 5000
	maxSearchMatches = 300
	maxSearchLineLen = 400
	maxSearchFileLen = 4 << 20
	readPageLines    = 4000
	readPageBytes    = 600 << 10
	verifyTailBytes  = 12 << 10
)

// errToolInput is a bad tool call from the agent: reported back to it as a
// failed result, never fatal for the run.
var errToolInput = errors.New("invalid tool input")

type toolRunner struct {
	root      string
	verifyCmd string
	vault     *secretVault
	changed   map[string]bool // repo paths created / edited / deleted
}

func newToolRunner(root, verifyCmd string) *toolRunner {
	return &toolRunner{root: root, verifyCmd: verifyCmd, vault: newSecretVault(), changed: map[string]bool{}}
}

// changedFiles lists every path the agent changed, sorted.
func (t *toolRunner) changedFiles() []string {
	var out []string
	for p := range t.changed {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// run executes calls in order; each gets a result (ok=false on error).
func (t *toolRunner) run(ctx context.Context, calls []appknox.KnoxFixerToolCall) []appknox.KnoxFixerToolResult {
	results := make([]appknox.KnoxFixerToolResult, 0, len(calls))
	for _, call := range calls {
		output, err := t.runOne(ctx, call)
		if err != nil {
			results = append(results, appknox.KnoxFixerToolResult{ID: call.ID, OK: false, Output: t.vault.mask(err.Error())})
			continue
		}
		results = append(results, appknox.KnoxFixerToolResult{ID: call.ID, OK: true, Output: output})
	}
	return results
}

func (t *toolRunner) runOne(ctx context.Context, call appknox.KnoxFixerToolCall) (string, error) {
	in := call.Input
	switch call.Name {
	case "list_files":
		return t.listFiles(str(in, "glob"))
	case "search":
		return t.search(str(in, "pattern"), str(in, "glob"))
	case "read_file":
		return t.readFile(str(in, "path"), num(in, "start_line"), num(in, "end_line"))
	case "edit_file":
		return t.editFile(str(in, "path"), str(in, "old_text"), str(in, "new_text"))
	case "create_file":
		return t.createFile(str(in, "path"), str(in, "content"))
	case "delete_file":
		return t.deleteFile(str(in, "path"))
	case "run_verify":
		return t.runVerify(ctx)
	}
	return "", fmt.Errorf("%w: unknown tool %q", errToolInput, call.Name)
}

func str(in map[string]interface{}, key string) string {
	if v, ok := in[key].(string); ok {
		return v
	}
	return ""
}

func num(in map[string]interface{}, key string) int {
	switch v := in[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

// --- paths ---------------------------------------------------------------------

// resolve maps a repo-relative path to disk. Anything outside the checkout,
// inside .git, or a secret/credential file is refused.
func (t *toolRunner) resolve(rel string) (string, error) {
	rel = strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(rel)), "./")
	if err := validateRepoRelPath(rel); err != nil {
		return "", fmt.Errorf("%w: %v", errToolInput, err)
	}
	if rel == ".git" || strings.HasPrefix(rel, ".git/") {
		return "", fmt.Errorf("%w: .git is not accessible", errToolInput)
	}
	if blockedFileRe.MatchString(rel) {
		return "", fmt.Errorf("%w: %s is a secret / credential file and is never read or written", errToolInput, rel)
	}
	return absRepoPath(t.root, rel)
}

func (t *toolRunner) walk(fn func(rel, abs string) bool) error {
	return filepath.WalkDir(t.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != t.root && skippedDirRe.MatchString(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := repoRelPath(t.root, p)
		// In a worktree .git is a file pointing at the main repository.
		if err != nil || rel == ".git" || blockedFileRe.MatchString(rel) {
			return nil
		}
		if !fn(rel, p) {
			return filepath.SkipAll
		}
		return nil
	})
}

// repoFiles lists the checkout (paths only) for the first agent step.
func (t *toolRunner) repoFiles(limit int) []string {
	var files []string
	t.walk(func(rel, _ string) bool {
		files = append(files, rel)
		return len(files) < limit
	})
	sort.Strings(files)
	return files
}

// --- read-only tools -------------------------------------------------------------

func (t *toolRunner) listFiles(glob string) (string, error) {
	var re *regexp.Regexp
	if strings.TrimSpace(glob) != "" {
		re = globToRegexp(strings.TrimSpace(glob))
	}
	var files []string
	truncated := false
	t.walk(func(rel, _ string) bool {
		if re == nil || re.MatchString(rel) {
			if len(files) >= maxListedFiles {
				truncated = true
				return false
			}
			files = append(files, rel)
		}
		return true
	})
	sort.Strings(files)
	out := strings.Join(files, "\n")
	if len(files) == 0 {
		out = "(no files match)"
	}
	if truncated {
		out += fmt.Sprintf("\n[only the first %d files; narrow the glob]", maxListedFiles)
	}
	return out, nil
}

func isBinary(data []byte) bool {
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}

func (t *toolRunner) search(pattern, glob string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("%w: bad regular expression: %v", errToolInput, err)
	}
	var fileRe *regexp.Regexp
	if strings.TrimSpace(glob) != "" {
		fileRe = globToRegexp(strings.TrimSpace(glob))
	}
	var matches []string
	truncated := false
	t.walk(func(rel, abs string) bool {
		if fileRe != nil && !fileRe.MatchString(rel) {
			return true
		}
		info, err := os.Stat(abs)
		if err != nil || info.Size() > maxSearchFileLen {
			return true
		}
		data, err := os.ReadFile(abs)
		if err != nil || isBinary(data) {
			return true
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64<<10), maxSearchFileLen)
		for n := 1; scanner.Scan(); n++ {
			line := scanner.Text()
			if !re.MatchString(line) {
				continue
			}
			if len(matches) >= maxSearchMatches {
				truncated = true
				return false
			}
			line = strings.TrimRight(line, "\r")
			if len(line) > maxSearchLineLen {
				line = line[:maxSearchLineLen] + "…"
			}
			matches = append(matches, fmt.Sprintf("%s:%d: %s", rel, n, line))
		}
		return true
	})
	out := strings.Join(matches, "\n")
	if len(matches) == 0 {
		out = "(no matches)"
	}
	if truncated {
		out += fmt.Sprintf("\n[only the first %d matches; narrow the pattern or glob]", maxSearchMatches)
	}
	return t.vault.mask(out), nil
}

func (t *toolRunner) readFile(rel string, start, end int) (string, error) {
	abs, err := t.resolve(rel)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", fmt.Errorf("%w: cannot read %s: %v", errToolInput, rel, err)
	}
	if isBinary(data) {
		return "", fmt.Errorf("%w: %s is a binary file", errToolInput, rel)
	}
	lines := strings.SplitAfter(t.vault.mask(string(data)), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	total := len(lines)
	if start < 1 {
		start = 1
	}
	if end < 1 || end > total {
		end = total
	}
	if total == 0 {
		return fmt.Sprintf("(%s is empty)", rel), nil
	}
	if start > total {
		return "", fmt.Errorf("%w: %s has only %d lines", errToolInput, rel, total)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%d lines)\n", rel, total)
	n := start
	for ; n <= end; n++ {
		if n-start >= readPageLines || b.Len() >= readPageBytes {
			break
		}
		fmt.Fprintf(&b, "%6d| %s", n, strings.TrimSuffix(lines[n-1], "\n"))
		b.WriteString("\n")
	}
	if n <= end {
		fmt.Fprintf(&b, "[truncated at line %d; read from line %d to continue]\n", n-1, n)
	}
	return b.String(), nil
}

// --- changing tools ------------------------------------------------------------------

func (t *toolRunner) editFile(rel, oldText, newText string) (string, error) {
	abs, err := t.resolve(rel)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", fmt.Errorf("%w: cannot read %s: %v (use create_file for new files)", errToolInput, rel, err)
	}
	if oldText == "" {
		return "", fmt.Errorf("%w: old_text is empty", errToolInput)
	}
	oldText, newText = t.vault.unmask(oldText), t.vault.unmask(newText)
	content := string(data)
	count := strings.Count(content, oldText)
	if count == 0 && strings.Contains(content, "\r\n") {
		count = strings.Count(content, strings.ReplaceAll(oldText, "\n", "\r\n"))
	}
	if count > 1 {
		return "", fmt.Errorf("%w: old_text occurs %d times in %s; include more surrounding lines", errToolInput, count, rel)
	}
	updated, ok := replaceOnce(content, oldText, newText)
	if !ok {
		return "", fmt.Errorf("%w: old_text not found in %s; read the file again", errToolInput, rel)
	}
	info, _ := os.Stat(abs)
	if err := os.WriteFile(abs, []byte(updated), info.Mode().Perm()); err != nil {
		return "", err
	}
	t.changed[rel] = true
	return "edited " + rel, nil
}

func (t *toolRunner) createFile(rel, content string) (string, error) {
	abs, err := t.resolve(rel)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(abs); err == nil {
		return "", fmt.Errorf("%w: %s already exists; use edit_file", errToolInput, rel)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(abs, []byte(t.vault.unmask(content)), 0o644); err != nil {
		return "", err
	}
	t.changed[rel] = true
	return "created " + rel, nil
}

func (t *toolRunner) deleteFile(rel string) (string, error) {
	abs, err := t.resolve(rel)
	if err != nil {
		return "", err
	}
	if err := os.Remove(abs); err != nil {
		return "", fmt.Errorf("%w: cannot delete %s: %v", errToolInput, rel, err)
	}
	t.changed[rel] = true
	return "deleted " + rel, nil
}

// replaceOnce applies one search/replace if the search block occurs exactly
// once, trying the file's CRLF line endings when the edit uses LF.
func replaceOnce(content, search, replace string) (string, bool) {
	if strings.Count(content, search) == 1 {
		return strings.Replace(content, search, replace, 1), true
	}
	if strings.Contains(content, "\r\n") && !strings.Contains(search, "\r\n") {
		crlfSearch := strings.ReplaceAll(search, "\n", "\r\n")
		if strings.Count(content, crlfSearch) == 1 {
			return strings.Replace(content, crlfSearch, strings.ReplaceAll(replace, "\n", "\r\n"), 1), true
		}
	}
	return content, false
}

// --- verify ---------------------------------------------------------------------------

func (t *toolRunner) runVerify(ctx context.Context) (string, error) {
	if t.verifyCmd == "" {
		return "", fmt.Errorf("%w: no --verify-cmd is configured", errToolInput)
	}
	ok, output := runVerifyCommand(ctx, t.root, t.verifyCmd)
	if len(output) > verifyTailBytes {
		output = "…" + output[len(output)-verifyTailBytes:]
	}
	status := "verify passed"
	if !ok {
		status = "verify FAILED"
	}
	return t.vault.mask(status + "\n" + output), nil
}

// runVerifyCommand runs the customer's own verify command (e.g. a compile
// task) in dir and returns whether it passed plus its combined output.
func runVerifyCommand(ctx context.Context, dir, command string) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return err == nil, out.String()
}

// --- secrets ----------------------------------------------------------------------------

// secretVault swaps secret-looking values for stable placeholders
// (__APPKNOX_SECRET_<n>__) in everything sent to the server, and swaps them
// back in what the agent writes, so a fix can move a secret (e.g. into a
// Gradle property) without the value ever leaving the runner.
type secretVault struct {
	mu      sync.Mutex
	byValue map[string]string
	byToken map[string]string
}

var secretTokenRe = regexp.MustCompile(`__APPKNOX_SECRET_\d+__`)

func newSecretVault() *secretVault {
	return &secretVault{byValue: map[string]string{}, byToken: map[string]string{}}
}

func (v *secretVault) token(value string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if tok, ok := v.byValue[value]; ok {
		return tok
	}
	tok := fmt.Sprintf("__APPKNOX_SECRET_%d__", len(v.byValue)+1)
	v.byValue[value], v.byToken[tok] = tok, value
	return tok
}

func (v *secretVault) mask(text string) string {
	text = privateKeyBlockRe.ReplaceAllStringFunc(text, func(block string) string {
		lines := strings.Split(block, "\n")
		for i, line := range lines {
			lines[i] = v.token(line)
		}
		return strings.Join(lines, "\n")
	})
	for _, re := range secretPatterns {
		if re.NumSubexp() == 3 {
			text = re.ReplaceAllStringFunc(text, func(m string) string {
				parts := re.FindStringSubmatch(m)
				return parts[1] + v.token(parts[2]) + parts[3]
			})
		} else {
			text = re.ReplaceAllStringFunc(text, v.token)
		}
	}
	return text
}

func (v *secretVault) unmask(text string) string {
	return secretTokenRe.ReplaceAllStringFunc(text, func(tok string) string {
		v.mu.Lock()
		defer v.mu.Unlock()
		if value, ok := v.byToken[tok]; ok {
			return value
		}
		return tok
	})
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{30,}`),
	regexp.MustCompile(`xox[abpr]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`),
	// key = "value" / key: 'value' / <string name="api_key">value</string>
	regexp.MustCompile(`(?i)((?:api[_-]?key|secret|token|passw(?:or)?d|pwd|private[_-]?key|client[_-]?secret|access[_-]?key)[A-Za-z0-9_\-]*["']?\s*(?:=|:|=>)\s*["'])([^"'\s]{6,})(["'])`),
	regexp.MustCompile(`(?i)(<string\s+name="[^"]*(?:key|secret|token|password)[^"]*"\s*>)([^<]{6,})(</string>)`),
}

var privateKeyBlockRe = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)
