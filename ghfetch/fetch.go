// Package ghfetch downloads a GitHub repository snapshot (tarball) to a local
// temp dir so the locate agent can run over it — for the standalone / "just a
// GitHub link" mode, where the repo isn't already checked out.
//
// This is client-side only: it pulls from GitHub with the caller's token and
// writes to the local machine. Nothing is uploaded, so the residency guarantee
// (only the located file reaches the Appknox gateway) is preserved.
package ghfetch

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultAPIBase  = "https://api.github.com"
	defaultMaxBytes = 512 * 1024 * 1024 // extracted-size cap (decompression-bomb guard)
	httpTimeout     = 120 * time.Second
)

// Config selects the repo/ref to fetch and the credentials/limits to use.
type Config struct {
	Owner    string // repo owner/org
	Repo     string // repo name
	Ref      string // branch, tag, or SHA; empty = default branch
	Token    string // GitHub token (optional for public repos)
	APIBase  string // GitHub API base; empty = https://api.github.com (set for GHES)
	MaxBytes int64  // extracted-size cap; <=0 = 512 MiB default
}

func (c Config) apiBase() string {
	if c.APIBase != "" {
		return strings.TrimRight(c.APIBase, "/")
	}
	return defaultAPIBase
}

func (c Config) maxBytes() int64 {
	if c.MaxBytes > 0 {
		return c.MaxBytes
	}
	return defaultMaxBytes
}

// tarballURL builds the GitHub tarball endpoint for the configured repo/ref.
func (c Config) tarballURL() string {
	u := fmt.Sprintf("%s/repos/%s/%s/tarball", c.apiBase(), c.Owner, c.Repo)
	if c.Ref != "" {
		u += "/" + c.Ref
	}
	return u
}

// FetchTarball downloads owner/repo@ref and extracts it into a fresh temp dir,
// returning that dir (the repo root) and a cleanup func the caller must invoke.
func FetchTarball(ctx context.Context, cfg Config) (string, func(), error) {
	if cfg.Owner == "" || cfg.Repo == "" {
		return "", nil, errors.New("ghfetch: owner and repo are required")
	}
	body, err := download(ctx, cfg)
	if err != nil {
		return "", nil, err
	}
	defer body.Close()

	root, err := os.MkdirTemp("", "appknox-autofix-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	if err := extractTarGz(body, root, cfg.maxBytes()); err != nil {
		cleanup()
		return "", nil, err
	}
	return root, cleanup, nil
}

// download issues the authenticated tarball request and returns the body stream.
func download(ctx context.Context, cfg Config) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.tarballURL(), nil)
	if err != nil {
		return nil, err
	}
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("ghfetch: GitHub tarball request returned HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// extractTarGz extracts a gzipped tar into root, stripping the tarball's top-level
// "<owner>-<repo>-<sha>/" directory. It writes only regular files and dirs
// (symlinks/hardlinks/devices are skipped, closing tar-slip via links), guards
// every path against escaping root (CWE-22), and caps total bytes written
// (decompression-bomb guard).
func extractTarGz(r io.Reader, root string, maxBytes int64) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("ghfetch: gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var written int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("ghfetch: tar: %w", err)
		}
		rel := stripTopDir(hdr.Name)
		if rel == "" {
			continue
		}
		dest, err := safeJoin(root, rel)
		if err != nil {
			return err
		}
		written, err = extractEntry(hdr, tr, dest, written, maxBytes)
		if err != nil {
			return err
		}
	}
}

// extractEntry writes one tar entry (dir or regular file) and returns the running
// byte total; non-regular entries (symlinks etc.) are skipped.
func extractEntry(hdr *tar.Header, r io.Reader, dest string, written, maxBytes int64) (int64, error) {
	switch hdr.Typeflag {
	case tar.TypeDir:
		return written, os.MkdirAll(dest, 0o755)
	case tar.TypeReg:
		n, err := writeFile(dest, r, maxBytes-written)
		return written + n, err
	default:
		return written, nil // skip symlinks/hardlinks/devices
	}
}

// writeFile creates dest and copies at most `budget` bytes from r, failing if the
// source would exceed the remaining extraction budget.
func writeFile(dest string, r io.Reader, budget int64) (int64, error) {
	if budget <= 0 {
		return 0, errors.New("ghfetch: extracted size cap exceeded")
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	n, err := io.Copy(f, io.LimitReader(r, budget+1))
	if err != nil {
		return n, err
	}
	if n > budget {
		return n, errors.New("ghfetch: extracted size cap exceeded")
	}
	return n, nil
}

// stripTopDir removes the tarball's leading "<owner>-<repo>-<sha>/" component and
// normalises the rest, neutralising any ".." so it cannot climb above the root.
func stripTopDir(name string) string {
	clean := strings.TrimPrefix(path.Clean("/"+name), "/")
	i := strings.IndexByte(clean, '/')
	if i < 0 {
		return "" // the top-level dir entry itself
	}
	return clean[i+1:]
}

// safeJoin resolves rel under root, rejecting any escape (CWE-22 tar-slip).
func safeJoin(root, rel string) (string, error) {
	dest := filepath.Join(root, rel)
	rp, err := filepath.Rel(root, dest)
	if err != nil || rp == ".." || strings.HasPrefix(rp, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("ghfetch: entry %q escapes root", rel)
	}
	return dest, nil
}
