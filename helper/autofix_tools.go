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
	"unicode/utf8"

	"github.com/appknox/appknox-go/appknox"
)

// The fix agent (on the server) asks for these tools; the CLI runs them in
// the autofix worktree of the customer's repository. Files are read in full
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
func (t *toolRunner) run(ctx context.Context, calls []appknox.AutofixToolCall) []appknox.AutofixToolResult {
	results := make([]appknox.AutofixToolResult, 0, len(calls))
	for _, call := range calls {
		output, err := t.runOne(ctx, call)
		if err != nil {
			results = append(results, appknox.AutofixToolResult{ID: call.ID, OK: false, Output: t.vault.mask(err.Error())})
			continue
		}
		results = append(results, appknox.AutofixToolResult{ID: call.ID, OK: true, Output: output})
	}
	return results
}

func (t *toolRunner) runOne(ctx context.Context, call appknox.AutofixToolCall) (string, error) {
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
	return "", fmt.Errorf("unknown tool %q", call.Name)
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

// resolve maps a repo-relative path to disk. Anything outside the checkout
// (including via a committed symlink), inside .git, or a secret/credential
// file is refused.
func (t *toolRunner) resolve(rel string) (string, error) {
	rel = strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(rel)), "./")
	if err := validateRepoRelPath(rel); err != nil {
		return "", fmt.Errorf("invalid tool input: %v", err)
	}
	if isDotGitPath(rel) {
		return "", errors.New("invalid tool input: .git is not accessible")
	}
	if blockedFileRe.MatchString(rel) {
		return "", fmt.Errorf("invalid tool input: %s is a secret / credential file and is never read or written", rel)
	}
	abs, err := absRepoPath(t.root, rel)
	if err != nil {
		return "", err
	}
	if err := ensureNoSymlinkEscape(t.root, abs); err != nil {
		return "", fmt.Errorf("invalid tool input: %v", err)
	}
	return abs, nil
}

// resolveForWrite is resolve plus a check against CI/build control files
// (.github/, .gitmodules, .gitattributes) that must stay read-only: editing
// them could change what runs during verify, which still has CI secrets.
func (t *toolRunner) resolveForWrite(rel string) (string, error) {
	abs, err := t.resolve(rel)
	if err != nil {
		return "", err
	}
	clean := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(rel)), "./")
	if blockedWritePathRe.MatchString(clean) {
		return "", fmt.Errorf("invalid tool input: %s is a CI/build control file and cannot be changed", clean)
	}
	return abs, nil
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
		if err != nil || isDotGitPath(rel) || blockedFileRe.MatchString(rel) {
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
	if err := t.walk(func(rel, _ string) bool {
		if re == nil || re.MatchString(rel) {
			if len(files) >= maxListedFiles {
				truncated = true
				return false
			}
			files = append(files, rel)
		}
		return true
	}); err != nil {
		return "", err
	}
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
		return "", fmt.Errorf("bad regular expression: %v", err)
	}
	var fileRe *regexp.Regexp
	if strings.TrimSpace(glob) != "" {
		fileRe = globToRegexp(strings.TrimSpace(glob))
	}
	var matches []string
	truncated := false
	if err := t.walk(func(rel, abs string) bool {
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
				line = truncateUTF8Head(line, maxSearchLineLen) + "…"
			}
			matches = append(matches, fmt.Sprintf("%s:%d: %s", rel, n, line))
		}
		return true
	}); err != nil {
		return "", err
	}
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
		return "", fmt.Errorf("cannot read %s", rel)
	}
	if isBinary(data) {
		return "", fmt.Errorf("%s is a binary file", rel)
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
		return "", fmt.Errorf("%s has only %d lines", rel, total)
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

// matchForReplace finds the single occurrence of oldText in content, trying
// the file's CRLF line endings when oldText uses LF, and returns the exact
// substring to replace plus its matching replacement. Counts occurrences
// exactly once (for the LF form, then the CRLF form only if LF had none).
func matchForReplace(content, oldText, newText string) (search, replace string, count int) {
	search, replace = oldText, newText
	count = strings.Count(content, search)
	if count == 0 && strings.Contains(content, "\r\n") && !strings.Contains(oldText, "\r\n") {
		search = strings.ReplaceAll(oldText, "\n", "\r\n")
		replace = strings.ReplaceAll(newText, "\n", "\r\n")
		count = strings.Count(content, search)
	}
	return search, replace, count
}

func (t *toolRunner) editFile(rel, oldText, newText string) (string, error) {
	abs, err := t.resolveForWrite(rel)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", fmt.Errorf("cannot read %s (use create_file for new files)", rel)
	}
	if oldText == "" {
		return "", errors.New("old_text is empty")
	}
	oldText, newText = t.vault.unmask(oldText), t.vault.unmask(newText)
	content := string(data)
	search, replace, count := matchForReplace(content, oldText, newText)
	switch count {
	case 0:
		return "", fmt.Errorf("old_text not found in %s; read the file again", rel)
	case 1:
	default:
		return "", fmt.Errorf("old_text occurs %d times in %s; include more surrounding lines", count, rel)
	}
	updated := strings.Replace(content, search, replace, 1)
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(abs, []byte(updated), info.Mode().Perm()); err != nil {
		return "", err
	}
	t.changed[rel] = true
	return "edited " + rel, nil
}

func (t *toolRunner) createFile(rel, content string) (string, error) {
	abs, err := t.resolveForWrite(rel)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(abs); err == nil {
		return "", fmt.Errorf("%s already exists; use edit_file", rel)
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
	abs, err := t.resolveForWrite(rel)
	if err != nil {
		return "", err
	}
	if err := os.Remove(abs); err != nil {
		return "", fmt.Errorf("cannot delete %s", rel)
	}
	t.changed[rel] = true
	return "deleted " + rel, nil
}

// --- verify ---------------------------------------------------------------------------

func (t *toolRunner) runVerify(ctx context.Context) (string, error) {
	if t.verifyCmd == "" {
		return "", errors.New("no --verify-cmd is configured")
	}
	ok, output := runVerifyCommand(ctx, t.root, t.verifyCmd)
	if len(output) > verifyTailBytes {
		output = "…" + truncateUTF8Tail(output, verifyTailBytes)
	}
	status := "verify passed"
	if !ok {
		status = "verify FAILED"
	}
	return t.vault.mask(status + "\n" + output), nil
}

// runVerifyCommand runs the customer's own verify command (e.g. a compile
// task) in dir and returns whether it passed plus its combined output. The
// command runs with CI secrets scrubbed from its environment: the agent can
// edit build scripts that this then executes, and the run still has
// GITHUB_TOKEN in its own environment at this point.
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
	cmd.Env = scrubbedVerifyEnv()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return err == nil, out.String()
}

// secretEnvKeyRe matches environment variable names that commonly hold CI
// credentials (tokens, keys, passwords) so verify never sees them.
var secretEnvKeyRe = regexp.MustCompile(`(?i)(TOKEN|SECRET|PASSWORD|PASSWD|_KEY$|APIKEY|CREDENTIAL)`)

// scrubbedVerifyEnv is the current process environment with CI-secret-shaped
// variables (GITHUB_TOKEN among them) removed.
func scrubbedVerifyEnv() []string {
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, kv := range env {
		key := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			key = kv[:i]
		}
		if key == "GITHUB_TOKEN" || secretEnvKeyRe.MatchString(key) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// truncateUTF8Head returns the first n bytes of s, backing off to the start
// of the previous rune if n would split a multi-byte UTF-8 character.
func truncateUTF8Head(s string, n int) string {
	for n > 0 && n < len(s) && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// truncateUTF8Tail returns the last n bytes of s, advancing to the start of
// the next rune if n would split a multi-byte UTF-8 character.
func truncateUTF8Tail(s string, n int) string {
	cut := len(s) - n
	for cut < len(s) && !utf8.RuneStart(s[cut]) {
		cut++
	}
	return s[cut:]
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
