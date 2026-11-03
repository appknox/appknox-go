package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/appknox/appknox-go/appknox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func writeEvent(t *testing.T, fork bool, headRepo string) string {
	t.Helper()
	event := map[string]interface{}{"pull_request": map[string]interface{}{
		"head": map[string]interface{}{"sha": "abc123", "repo": map[string]interface{}{"full_name": headRepo, "fork": fork}},
		"base": map[string]interface{}{"repo": map[string]interface{}{"full_name": "acme/app"}},
	}}
	data, _ := json.Marshal(event)
	path := filepath.Join(t.TempDir(), "event.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func baseEnv() map[string]string {
	return map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/app", "GITHUB_SERVER_URL": "https://github.com",
		"GITHUB_EVENT_NAME": "push", "GITHUB_REF_NAME": "main", "GITHUB_SHA": "deadbeef",
	}
}

func TestKnoxFixerEnvPush(t *testing.T) {
	env, err := readKnoxFixerCIEnv(envFrom(baseEnv()))
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/acme/app", env.RepoURL)
	assert.Equal(t, "main", env.BaseBranch)
	assert.Equal(t, "deadbeef", env.BaseSHA)
}

func TestKnoxFixerEnvPullRequestUsesHeadBranchAndSHA(t *testing.T) {
	m := baseEnv()
	m["GITHUB_EVENT_NAME"] = "pull_request"
	m["GITHUB_HEAD_REF"] = "feature/x"
	m["GITHUB_EVENT_PATH"] = writeEvent(t, false, "acme/app")
	env, err := readKnoxFixerCIEnv(envFrom(m))
	require.NoError(t, err)
	assert.Equal(t, "feature/x", env.BaseBranch)
	assert.Equal(t, "abc123", env.BaseSHA)
}

func TestKnoxFixerEnvRefusals(t *testing.T) {
	fork := baseEnv()
	fork["GITHUB_EVENT_NAME"] = "pull_request"
	fork["GITHUB_HEAD_REF"] = "x"
	fork["GITHUB_EVENT_PATH"] = writeEvent(t, true, "evil/app")
	target := baseEnv()
	target["GITHUB_EVENT_NAME"] = "pull_request_target"
	tag := baseEnv()
	tag["GITHUB_REF_TYPE"] = "tag"
	notGH := baseEnv()
	delete(notGH, "GITHUB_ACTIONS")
	for name, m := range map[string]map[string]string{"fork": fork, "target": target, "tag": tag, "not_github": notGH} {
		_, err := readKnoxFixerCIEnv(envFrom(m))
		assert.Error(t, err, name)
		assert.NotErrorIs(t, err, errKnoxFixerBranchSkip, name)
	}
}

func TestKnoxFixerEnvOwnBranchIsSkipped(t *testing.T) {
	m := baseEnv()
	m["GITHUB_REF_NAME"] = "appknox-knoxfixer/main"
	_, err := readKnoxFixerCIEnv(envFrom(m))
	assert.ErrorIs(t, err, errKnoxFixerBranchSkip)
}

func TestResolveFileID(t *testing.T) {
	id, err := resolveKnoxFixerFileID(12, envFrom(map[string]string{"APPKNOX_FILE_ID": "99"}))
	require.NoError(t, err)
	assert.Equal(t, 12, id)
	id, err = resolveKnoxFixerFileID(0, envFrom(map[string]string{"APPKNOX_FILE_ID": " 99 "}))
	require.NoError(t, err)
	assert.Equal(t, 99, id)
	_, err = resolveKnoxFixerFileID(0, envFrom(map[string]string{}))
	assert.Equal(t, errNoFileID, err)
	_, err = resolveKnoxFixerFileID(0, envFrom(map[string]string{"APPKNOX_FILE_ID": "abc"}))
	assert.Error(t, err)
}

func TestGlobAndPaths(t *testing.T) {
	assert.True(t, globToRegexp("**/com/acme/A.kt").MatchString("app/src/main/java/com/acme/A.kt"))
	assert.True(t, globToRegexp("**/AndroidManifest.xml").MatchString("AndroidManifest.xml"))
	assert.False(t, globToRegexp("**/A.kt").MatchString("app/B.kt"))
	assert.False(t, globToRegexp("app/*.kt").MatchString("app/x/A.kt"))
	for _, bad := range []string{"/abs/x", "./x", "../x", "a/../../x", `a\b`, "C:/x"} {
		assert.Error(t, validateRepoRelPath(bad), bad)
	}
}

func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o755))
		require.NoError(t, os.WriteFile(abs, []byte(content), 0o644))
	}
	return root
}

func call(id, name string, input map[string]interface{}) appknox.KnoxFixerToolCall {
	return appknox.KnoxFixerToolCall{ID: id, Name: name, Input: input}
}

func runTool(t *testing.T, tr *toolRunner, name string, input map[string]interface{}) appknox.KnoxFixerToolResult {
	t.Helper()
	res := tr.run(context.Background(), []appknox.KnoxFixerToolCall{call("t", name, input)})
	require.Len(t, res, 1)
	return res[0]
}

func fixtureRepo(t *testing.T) string {
	return writeRepo(t, map[string]string{
		"app/src/main/AndroidManifest.xml":    "<manifest>\r\n    <application android:allowBackup=\"true\">\r\n    </application>\r\n</manifest>\r\n",
		"app/src/main/java/com/acme/Login.kt": "class Login {\n    val apiKey = \"abcdef123456\"\n    fun onClick() {}\n}\n",
		"app/build.gradle":                    "android {\n    buildTypes {\n        release {\n            minifyEnabled false\n        }\n    }\n}\n",
		".github/workflows/ci.yml":            "on: push\n",
		"app/google-services.json":            "{\"key\": \"x\"}",
		"app/build/generated/Gen.kt":          "x",
	})
}

func TestToolsListAndSearch(t *testing.T) {
	tr := newToolRunner(fixtureRepo(t), "")
	files := tr.repoFiles(1000)
	assert.Contains(t, files, "app/build.gradle")
	assert.Contains(t, files, ".github/workflows/ci.yml") // CI files are editable now
	assert.NotContains(t, files, "app/google-services.json")
	assert.NotContains(t, files, "app/build/generated/Gen.kt")

	res := runTool(t, tr, "list_files", map[string]interface{}{"glob": "**/*.gradle"})
	assert.True(t, res.OK)
	assert.Equal(t, "app/build.gradle", res.Output)

	res = runTool(t, tr, "search", map[string]interface{}{"pattern": `allowBackup|minifyEnabled`, "glob": ""})
	assert.True(t, res.OK)
	assert.Contains(t, res.Output, "app/src/main/AndroidManifest.xml:2:")
	assert.Contains(t, res.Output, "app/build.gradle:4:")

	res = runTool(t, tr, "search", map[string]interface{}{"pattern": "(", "glob": ""})
	assert.False(t, res.OK)
}

func TestToolsReadWholeFileWithSecretsMasked(t *testing.T) {
	tr := newToolRunner(fixtureRepo(t), "")
	res := runTool(t, tr, "read_file", map[string]interface{}{"path": "app/src/main/java/com/acme/Login.kt", "start_line": 0.0, "end_line": 0.0})
	require.True(t, res.OK)
	assert.Contains(t, res.Output, "     1| class Login {")
	assert.Contains(t, res.Output, "     4| }")
	assert.NotContains(t, res.Output, "abcdef123456")
	assert.Contains(t, res.Output, "__APPKNOX_SECRET_1__")

	res = runTool(t, tr, "read_file", map[string]interface{}{"path": "app/google-services.json"})
	assert.False(t, res.OK)
	res = runTool(t, tr, "read_file", map[string]interface{}{"path": "../outside.txt"})
	assert.False(t, res.OK)
	res = runTool(t, tr, "read_file", map[string]interface{}{"path": ".git/config"})
	assert.False(t, res.OK)
}

func TestToolsEditCreateDelete(t *testing.T) {
	root := fixtureRepo(t)
	tr := newToolRunner(root, "")

	// LF edit on a CRLF file keeps CRLF
	res := runTool(t, tr, "edit_file", map[string]interface{}{
		"path":     "app/src/main/AndroidManifest.xml",
		"old_text": "<manifest>\n    <application android:allowBackup=\"true\">",
		"new_text": "<manifest>\n    <application android:allowBackup=\"false\">",
	})
	require.True(t, res.OK, res.Output)
	data, _ := os.ReadFile(filepath.Join(root, "app/src/main/AndroidManifest.xml"))
	assert.Contains(t, string(data), "<manifest>\r\n    <application android:allowBackup=\"false\">")

	// a masked secret moved by the agent is written back with its real value
	runTool(t, tr, "read_file", map[string]interface{}{"path": "app/src/main/java/com/acme/Login.kt"})
	res = runTool(t, tr, "edit_file", map[string]interface{}{
		"path":     "app/src/main/java/com/acme/Login.kt",
		"old_text": "    val apiKey = \"__APPKNOX_SECRET_1__\"\n",
		"new_text": "    val apiKey = BuildConfig.API_KEY\n",
	})
	require.True(t, res.OK, res.Output)
	res = runTool(t, tr, "edit_file", map[string]interface{}{
		"path":     "app/build.gradle",
		"old_text": "            minifyEnabled false\n",
		"new_text": "            minifyEnabled true\n            buildConfigField \"String\", \"API_KEY\", \"\\\"__APPKNOX_SECRET_1__\\\"\"\n",
	})
	require.True(t, res.OK, res.Output)
	gradle, _ := os.ReadFile(filepath.Join(root, "app/build.gradle"))
	assert.Contains(t, string(gradle), `abcdef123456`)
	assert.Contains(t, string(gradle), "minifyEnabled true")

	// not unique / not found
	res = runTool(t, tr, "edit_file", map[string]interface{}{"path": "app/build.gradle", "old_text": "    ", "new_text": "x"})
	assert.False(t, res.OK)
	assert.Contains(t, res.Output, "occurs")
	res = runTool(t, tr, "edit_file", map[string]interface{}{"path": "app/build.gradle", "old_text": "nope", "new_text": "x"})
	assert.False(t, res.OK)

	// new file, existing file refused, delete
	res = runTool(t, tr, "create_file", map[string]interface{}{"path": "app/src/main/res/xml/network_security_config.xml", "content": "<network-security-config/>\n"})
	require.True(t, res.OK, res.Output)
	res = runTool(t, tr, "create_file", map[string]interface{}{"path": "app/build.gradle", "content": "x"})
	assert.False(t, res.OK)
	res = runTool(t, tr, "delete_file", map[string]interface{}{"path": ".github/workflows/ci.yml"})
	require.True(t, res.OK, res.Output)
	res = runTool(t, tr, "create_file", map[string]interface{}{"path": ".env", "content": "x"})
	assert.False(t, res.OK)

	assert.Equal(t, []string{
		".github/workflows/ci.yml",
		"app/build.gradle",
		"app/src/main/AndroidManifest.xml",
		"app/src/main/java/com/acme/Login.kt",
		"app/src/main/res/xml/network_security_config.xml",
	}, tr.changedFiles())
}

func TestToolsVerify(t *testing.T) {
	root := fixtureRepo(t)
	res := runTool(t, newToolRunner(root, ""), "run_verify", map[string]interface{}{})
	assert.False(t, res.OK)
	res = runTool(t, newToolRunner(root, "exit 3"), "run_verify", map[string]interface{}{})
	assert.True(t, res.OK)
	assert.Contains(t, res.Output, "verify FAILED")
	res = runTool(t, newToolRunner(root, "echo fine"), "run_verify", map[string]interface{}{})
	assert.Contains(t, res.Output, "verify passed")
}

func TestToolsUnknownTool(t *testing.T) {
	res := runTool(t, newToolRunner(t.TempDir(), ""), "rm_rf", map[string]interface{}{})
	assert.False(t, res.OK)
}

func TestReadFilePaging(t *testing.T) {
	var b strings.Builder
	for i := 0; i < readPageLines+10; i++ {
		b.WriteString("x\n")
	}
	tr := newToolRunner(writeRepo(t, map[string]string{"big.txt": b.String()}), "")
	res := runTool(t, tr, "read_file", map[string]interface{}{"path": "big.txt"})
	require.True(t, res.OK)
	assert.Contains(t, res.Output, fmt.Sprintf("read from line %d", readPageLines+1))
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := (&gitRunner{dir: dir}).run(context.Background(), args...)
	require.NoError(t, err, strings.Join(args, " "))
	return out
}

func TestMergeTheirsKeepsBaseOnConflict(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := writeRepo(t, map[string]string{"a.kt": "one\ntwo\nthree\n", "b.kt": "keep\n"})
	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "init")
	git(t, dir, "checkout", "-q", "-b", "fix")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.kt"), []byte("one\nFIX\nthree\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.kt"), []byte("keep-fixed\n"), 0o644))
	git(t, dir, "commit", "-q", "-am", "fix")
	git(t, dir, "checkout", "-q", "main")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.kt"), []byte("one\nBASE\nthree\n"), 0o644))
	git(t, dir, "commit", "-q", "-am", "base change")
	baseSHA := git(t, dir, "rev-parse", "HEAD")
	git(t, dir, "checkout", "-q", "fix")

	conflicts, err := (&gitRunner{dir: dir}).mergeTheirs(context.Background(), baseSHA)
	require.NoError(t, err)
	assert.Equal(t, []string{"a.kt"}, conflicts)
	a, _ := os.ReadFile(filepath.Join(dir, "a.kt"))
	b, _ := os.ReadFile(filepath.Join(dir, "b.kt"))
	assert.Equal(t, "one\nBASE\nthree\n", strings.ReplaceAll(string(a), "\r\n", "\n"))
	assert.Equal(t, "keep-fixed\n", strings.ReplaceAll(string(b), "\r\n", "\n")) // non-conflict fix kept
}

func TestLatestKnoxFixerPR(t *testing.T) {
	prs := `[
	 {"number": 3, "state": "closed", "merged_at": null, "created_at": "2026-10-03T00:00:00Z", "head": {"ref": "appknox-knoxfixer/main", "sha": "s3"}},
	 {"number": 2, "state": "closed", "merged_at": null, "created_at": "2026-10-02T00:00:00Z", "head": {"ref": "appknox-knoxfixer/main", "sha": "s2"}},
	 {"number": 1, "state": "closed", "merged_at": "2026-10-01T05:00:00Z", "created_at": "2026-10-01T00:00:00Z", "head": {"ref": "appknox-knoxfixer/main", "sha": "s1"}}
	]`
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		w.Write([]byte(prs))
	}))
	defer srv.Close()
	gh := newGitHubClient(srv.URL, "acme/app", "tok")
	pr, open, err := gh.latestKnoxFixerPR(context.Background(), "appknox-knoxfixer/main", "main")
	require.NoError(t, err)
	assert.Equal(t, 3, pr.Number) // newest closed-unmerged → reopen candidate
	assert.Equal(t, 0, open)
	assert.Contains(t, gotQuery, "state=all")
	assert.Contains(t, gotQuery, "head=acme%3Aappknox-knoxfixer%2Fmain")
}

func TestReopenRestoresDeletedBranch(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/branches/"):
			w.WriteHeader(404)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/git/refs"):
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			assert.Equal(t, "s3", body["sha"])
			w.WriteHeader(201)
		case r.Method == "PATCH":
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	run := &knoxFixerRun{ctx: context.Background(), gh: newGitHubClient(srv.URL, "acme/app", "tok"), head: "appknox-knoxfixer/main"}
	pr := &githubPR{Number: 3}
	pr.Head.SHA = "s3"
	assert.True(t, run.reopen(pr))
	assert.Equal(t, []string{
		"GET /repos/acme/app/branches/appknox-knoxfixer/main",
		"POST /repos/acme/app/git/refs",
		"PATCH /repos/acme/app/pulls/3",
	}, calls)
}

func TestReopenFailureFallsBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" {
			w.WriteHeader(422)
			w.Write([]byte(`{"message":"state cannot be changed"}`))
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	run := &knoxFixerRun{ctx: context.Background(), gh: newGitHubClient(srv.URL, "acme/app", "tok"), head: "appknox-knoxfixer/main"}
	assert.False(t, run.reopen(&githubPR{Number: 3}))
}

func TestPrCreateHint(t *testing.T) {
	err := &githubAPIError{StatusCode: 403, Message: "GitHub Actions is not permitted to create or approve pull requests."}
	assert.Contains(t, prCreateHint(err), "Allow GitHub Actions")
}
