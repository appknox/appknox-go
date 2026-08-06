package ghfetch

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type tarEntry struct {
	name string
	typ  byte
	body string
	link string
}

func makeTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644, Size: int64(len(e.body))}
		if e.typ == tar.TypeSymlink {
			hdr.Linkname = e.link
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if e.typ == tar.TypeReg {
			_, err := tw.Write([]byte(e.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

const top = "acme-repo-abc123/" // GitHub's "<owner>-<repo>-<sha>/" prefix

func TestExtractTarGz_StripsTopDirAndWritesFiles(t *testing.T) {
	root := t.TempDir()
	data := makeTarGz(t, []tarEntry{
		{name: top, typ: tar.TypeDir},
		{name: top + "app/", typ: tar.TypeDir},
		{name: top + "app/Main.java", typ: tar.TypeReg, body: "new Random()"},
		{name: top + "README.md", typ: tar.TypeReg, body: "hi"},
	})
	require.NoError(t, extractTarGz(bytes.NewReader(data), root, defaultMaxBytes))

	body, err := os.ReadFile(filepath.Join(root, "app/Main.java"))
	require.NoError(t, err)
	require.Contains(t, string(body), "Random")     // top dir stripped
	require.FileExists(t, filepath.Join(root, "README.md"))
}

func TestExtractTarGz_SkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	data := makeTarGz(t, []tarEntry{
		{name: top + "app.go", typ: tar.TypeReg, body: "x"},
		{name: top + "creds", typ: tar.TypeSymlink, link: "/etc/passwd"},
	})
	require.NoError(t, extractTarGz(bytes.NewReader(data), root, defaultMaxBytes))
	require.FileExists(t, filepath.Join(root, "app.go"))
	require.NoFileExists(t, filepath.Join(root, "creds")) // symlink not created
}

func TestExtractTarGz_TraversalStaysContained(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "evil.txt")
	data := makeTarGz(t, []tarEntry{
		{name: top + "../../../../../../tmp/evil.txt", typ: tar.TypeReg, body: "pwned"},
		{name: top + "ok.go", typ: tar.TypeReg, body: "ok"},
	})
	require.NoError(t, extractTarGz(bytes.NewReader(data), root, defaultMaxBytes))
	require.NoFileExists(t, outside)             // never escaped root
	require.FileExists(t, filepath.Join(root, "ok.go"))
}

func TestExtractTarGz_SizeCapExceeded(t *testing.T) {
	root := t.TempDir()
	data := makeTarGz(t, []tarEntry{
		{name: top + "big.txt", typ: tar.TypeReg, body: string(make([]byte, 2000))},
	})
	err := extractTarGz(bytes.NewReader(data), root, 1000)
	require.Error(t, err)
}

func TestStripTopDir(t *testing.T) {
	require.Equal(t, "app/Main.java", stripTopDir("acme-repo-abc/app/Main.java"))
	require.Equal(t, "", stripTopDir("acme-repo-abc/"))               // top dir itself
	require.Equal(t, "", stripTopDir("acme-repo-abc"))               // bare top, no child
	require.Equal(t, "Main.java", stripTopDir("acme/sub/../Main.java")) // interior .. collapses
	require.Equal(t, "", stripTopDir("acme/../../evil.txt"))          // escape neutralised -> dropped
}

func TestSafeJoin(t *testing.T) {
	root := t.TempDir()
	dest, err := safeJoin(root, "app/Main.java")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(root, "app/Main.java"), dest)

	_, err = safeJoin(root, "../escape")
	require.Error(t, err)
}

func TestFetchTarball_RequiresOwnerRepo(t *testing.T) {
	_, _, err := FetchTarball(context.Background(), Config{Repo: "r"})
	require.Error(t, err)
}

func TestFetchTarball_EndToEndViaTestServer(t *testing.T) {
	data := makeTarGz(t, []tarEntry{
		{name: top + "app/Main.java", typ: tar.TypeReg, body: "new Random()"},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/repos/o/r/tarball/main", r.URL.Path)
		require.Equal(t, "Bearer TKN", r.Header.Get("Authorization"))
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	root, cleanup, err := FetchTarball(context.Background(), Config{
		Owner: "o", Repo: "r", Ref: "main", Token: "TKN", APIBase: srv.URL,
	})
	require.NoError(t, err)
	defer cleanup()
	body, err := os.ReadFile(filepath.Join(root, "app/Main.java"))
	require.NoError(t, err)
	require.Contains(t, string(body), "Random")
}

func TestFetchTarball_HTTPErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	_, _, err := FetchTarball(context.Background(), Config{Owner: "o", Repo: "r", APIBase: srv.URL})
	require.Error(t, err)
}

func TestConfig_TarballURL(t *testing.T) {
	require.Equal(t,
		"https://api.github.com/repos/o/r/tarball/main",
		Config{Owner: "o", Repo: "r", Ref: "main"}.tarballURL())
	require.Equal(t,
		"https://api.github.com/repos/o/r/tarball",
		Config{Owner: "o", Repo: "r"}.tarballURL()) // no ref
	require.Equal(t,
		"https://ghe.corp/api/v3/repos/o/r/tarball",
		Config{Owner: "o", Repo: "r", APIBase: "https://ghe.corp/api/v3"}.tarballURL())
}
