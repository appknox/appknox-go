package agent

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxReadBytes = 256 * 1024 // cap a single read_file result
	maxScanBytes = 512 * 1024 // skip files larger than this when grepping
	maxMatches   = 40         // cap grep/glob result lines to keep tool output small
)

// skipDirs are build/vendor/VCS directories never worth searching for source.
var skipDirs = map[string]bool{
	"node_modules": true, "build": true, "dist": true, "out": true,
	"vendor": true, "target": true, "Pods": true, "__pycache__": true,
	"DerivedData": true, "bin": true, "obj": true,
}

// sourceSuffixes are the file extensions treated as fixable source.
var sourceSuffixes = map[string]bool{
	".java": true, ".kt": true, ".kts": true, ".swift": true, ".m": true,
	".mm": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".c": true, ".cc": true, ".cpp": true, ".h": true, ".hpp": true,
	".cs": true, ".go": true, ".py": true, ".rb": true, ".php": true, ".xml": true,
}

// skipDir reports whether a directory should be pruned from the walk.
func skipDir(name string) bool {
	return skipDirs[name] || (len(name) > 1 && strings.HasPrefix(name, "."))
}

// isSource reports whether a path has a recognised source extension.
func isSource(rel string) bool {
	return sourceSuffixes[strings.ToLower(filepath.Ext(rel))]
}

// walkSourceFiles calls fn(rel, abs) for every real (non-symlink) source file
// under root, pruning build/vendor dirs. Symlinks are skipped so the walk can
// never follow a link out of the tree (CWE-59); non-source files are excluded so
// grep/glob only ever surface fixable source. fn may return filepath.SkipAll to
// stop early.
func walkSourceFiles(root string, fn func(rel, abs string) error) {
	_ = filepath.WalkDir(root, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, never abort the whole walk
		}
		if d.IsDir() {
			if abs != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never read through a symlink
		}
		rel, relErr := filepath.Rel(root, abs)
		if relErr != nil || !isSource(rel) {
			return nil
		}
		return fn(filepath.ToSlash(rel), abs)
	})
}

// readCapped reads up to limit bytes from abs without loading larger files whole,
// reporting whether the file exceeded the cap (and was therefore truncated).
func readCapped(abs string, limit int64) ([]byte, bool, error) {
	f, err := os.Open(abs)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}
