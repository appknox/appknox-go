package helper

import (
	"context"
	"encoding/json"
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
	assert.False(t, isReadableRepoFile("app/google-services.json"))
	assert.False(t, isReadableRepoFile(".env"))
	assert.False(t, isReadableRepoFile("app/release.keystore"))
	assert.False(t, isEditableRepoFile("App.xcodeproj/project.pbxproj"))
	assert.False(t, isEditableRepoFile(".github/workflows/ci.yml"))
	assert.True(t, isEditableRepoFile("app/src/main/AndroidManifest.xml"))
}

func TestMaskSecrets(t *testing.T) {
	in := "val apiKey = \"abcdef123456\"\nval aws = \"AKIAABCDEFGHIJKLMNOP\"\n<string name=\"maps_key\">AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</string>\nval x = 1\n"
	out := maskSecrets(in)
	assert.NotContains(t, out, "abcdef123456")
	assert.NotContains(t, out, "AKIAABCDEFGHIJKLMNOP")
	assert.NotContains(t, out, "AIzaSy")
	assert.Contains(t, out, "val x = 1")
	assert.Equal(t, strings.Count(in, "\n"), strings.Count(out, "\n"))
}

func TestMergeRanges(t *testing.T) {
	merged := mergeRanges([]lineRange{
		{start: 1, end: 120, refs: []string{"a"}},
		{start: 100, end: 219, refs: []string{"b"}},
		{start: 220, end: 339, refs: []string{"c"}}, // touching → merged
		{start: 500, end: 619, refs: []string{"d"}},
	})
	require.Len(t, merged, 2)
	assert.Equal(t, []string{"a", "b", "c"}, merged[0].refs)
	assert.LessOrEqual(t, merged[0].end-merged[0].start+1, 120*len(merged[0].refs))
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

func TestLocateAndSnippets(t *testing.T) {
	var manifest strings.Builder
	for i := 1; i <= 300; i++ {
		if i == 150 {
			manifest.WriteString("    <application android:debuggable=\"true\">\n")
			continue
		}
		manifest.WriteString("<!-- line -->\n")
	}
	root := writeRepo(t, map[string]string{
		"app/src/main/AndroidManifest.xml":    manifest.String(),
		"lib/src/main/AndroidManifest.xml":    "<manifest/>\n",
		"app/src/main/java/com/acme/Login.kt": "class Login {\n fun onClick() {}\n}\n",
		"app/src/test/java/com/acme/Login.kt": "class LoginTest\n",
		"app/google-services.json":            "{}",
		"app/build/generated/com/acme/Gen.kt": "x",
	})
	idx, err := buildRepoIndex(root, "")
	require.NoError(t, err)
	assert.NotContains(t, idx.files, "app/google-services.json")
	assert.NotContains(t, idx.files, "app/build/generated/com/acme/Gen.kt")

	findings := []appknox.KnoxFixerPlanFinding{
		{Ref: "f_1", Locate: appknox.KnoxFixerLocate{Kind: "android_manifest",
			PathGlobs: []string{"**/src/main/AndroidManifest.xml"}, SearchTerms: []string{"android:debuggable"}}},
		{Ref: "f_2", Locate: appknox.KnoxFixerLocate{Kind: "source",
			PathGlobs: []string{"**/com/acme/Login.kt"}, SearchTerms: []string{"onClick"}}},
		{Ref: "f_3", Locate: appknox.KnoxFixerLocate{Kind: "source", PathGlobs: []string{"**/Nope.kt"}}},
	}
	located, unresolved := locateFindings(idx, findings)
	assert.Equal(t, []string{"f_3"}, unresolved)
	require.Len(t, located, 2)
	assert.Equal(t, "app/src/main/AndroidManifest.xml", located[0].Path)
	assert.Equal(t, 150, located[0].Line)
	assert.Equal(t, "app/src/main/java/com/acme/Login.kt", located[1].Path)

	snippets, failed := buildSnippets(idx, located, 120)
	assert.Empty(t, failed)
	for _, s := range snippets {
		assert.LessOrEqual(t, s.EndLine-s.StartLine+1, 120*len(s.Refs))
		assert.Equal(t, s.EndLine-s.StartLine+1, strings.Count(s.Content, "\n"))
	}
}

func TestApplyEdits(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"a.xml": "line1\r\nandroid:debuggable=\"true\"\r\nline3\r\n",
		"b.kt":  "val r = Random()\nval s = Random()\n",
	})
	edits := []appknox.KnoxFixerEdit{
		// LF edit on a CRLF file
		{Ref: "f_1", Path: "a.xml", Search: "line1\nandroid:debuggable=\"true\"", Replace: "line1\nandroid:debuggable=\"false\""},
		// same edit for a second finding: applied once, counted for both
		{Ref: "f_2", Path: "a.xml", Search: "line1\nandroid:debuggable=\"true\"", Replace: "line1\nandroid:debuggable=\"false\""},
		// not unique → whole finding skipped
		{Ref: "f_3", Path: "b.kt", Search: "Random()", Replace: "SecureRandom()"},
		{Ref: "f_4", Path: ".github/workflows/x.yml", Search: "a", Replace: "b"},
	}
	res, _, err := applyEdits(root, edits)
	require.NoError(t, err)
	data, _ := os.ReadFile(filepath.Join(root, "a.xml"))
	assert.Equal(t, "line1\r\nandroid:debuggable=\"false\"\r\nline3\r\n", string(data))
	assert.Equal(t, []string{"a.xml"}, res.FilesByRef["f_1"])
	assert.Equal(t, []string{"a.xml"}, res.FilesByRef["f_2"])
	assert.NotContains(t, res.FilesByRef, "f_3")
	assert.NotContains(t, res.FilesByRef, "f_4")
	assert.Len(t, res.Skipped, 2)
	assert.Equal(t, []string{"a.xml"}, res.Files)
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
