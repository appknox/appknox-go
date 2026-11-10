package helper

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/appknox/appknox-go/agent"
)

// New files: a remediation that creates a file (mfva 113's
// res/xml/network_security_config.xml, 16's SecureCryptoManager) names it in
// the locate reply's new_files. The model decides WHAT the remediation
// creates; code decides WHERE it may go, before anything is written.

const (
	reasonNewExists      = "already exists"
	reasonNewPlacement   = "not in a module source set (src/<set>/res/<type>/ or src/<set>/java|kotlin/)"
	reasonNewResName     = "resource file name must be lowercase letters, digits and underscores"
	reasonNewUnsupported = "new files may only be resource XML, Java or Kotlin"

	// reasonNewFileRejected is a whole finding's SKIPPED reason when a file
	// its remediation creates failed validation: the rest of the remediation
	// refers to that file, so none of it is applied.
	reasonNewFileRejected = "new file refused"
)

// xmlResourceTypes are the res/ directories (before any -qualifier) that hold
// XML resources AAPT accepts.
var xmlResourceTypes = map[string]bool{
	"anim": true, "animator": true, "color": true, "drawable": true, "font": true, "layout": true,
	"menu": true, "mipmap": true, "navigation": true, "transition": true, "values": true, "xml": true,
}

// resourceNameRE is Android's rule for a resource file's base name.
var resourceNameRE = regexp.MustCompile(`^[a-z0-9_]+$`)

// validateNewFiles checks each new_files entry. A path that turns out to
// exist is not refused: it is handed back in existing, to be fixed as an
// ordinary target (the second of mfva 16's findings names the
// SecureCryptoManager the first one already created).
func validateNewFiles(root string, entries []agent.Target) (created, existing []agent.Target, rejected []rejection) {
	seen := map[string]bool{}
	for _, t := range entries {
		rel, reason := checkNewTarget(root, t.Path)
		switch {
		case reason == reasonNewExists:
			existing = append(existing, agent.Target{Path: rel, Why: t.Why})
		case reason != "":
			rejected = append(rejected, rejection{Path: t.Path, Reason: reason})
		case !seen[rel]:
			seen[rel] = true
			created = append(created, agent.Target{Path: rel, Why: t.Why, New: true})
		}
	}
	return created, existing, rejected
}

// checkNewTarget returns the cleaned repo-relative path, or why it may not be
// created. reasonNewExists carries the cleaned path too.
func checkNewTarget(root, raw string) (string, string) {
	rel := filepath.ToSlash(filepath.Clean(strings.TrimSpace(raw)))
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		return "", reasonInvalidPath
	}
	dest, err := safeDest(root, rel)
	if err != nil {
		return "", reasonInvalidPath
	}
	_, statErr := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	if statErr == nil {
		return rel, reasonNewExists
	}
	if !errors.Is(statErr, fs.ErrNotExist) {
		return "", reasonInvalidPath
	}
	if prunedComponent(root, dest) {
		return "", reasonGenerated
	}
	if buildFileRE.MatchString(rel) || moduleBuildScriptRE.MatchString(rel) {
		return "", reasonBuildFile
	}
	return rel, newPlacementReason(rel)
}

// newPlacementReason checks where a new file sits inside a module:
// <module>/src/<set>/res/<type>/<name>.xml, or a Java/Kotlin file under
// <module>/src/<set>/java/ or kotlin/ with at least one package directory.
func newPlacementReason(rel string) string {
	parts := strings.Split(rel, "/")
	src := -1
	for i, p := range parts {
		if p == "src" {
			src = i
		}
	}
	// src, <set>, (res|java|kotlin), then at least <dir>/<file>.
	if src < 0 || len(parts) < src+5 {
		return reasonNewPlacement
	}
	kind, name := parts[src+2], parts[len(parts)-1]
	switch strings.ToLower(path.Ext(name)) {
	case ".xml":
		if kind != "res" || len(parts) != src+5 || !xmlResourceTypes[strings.SplitN(parts[src+3], "-", 2)[0]] {
			return reasonNewPlacement
		}
		if !resourceNameRE.MatchString(strings.TrimSuffix(name, path.Ext(name))) {
			return reasonNewResName
		}
		return ""
	case ".java", ".kt":
		if kind != "java" && kind != "kotlin" {
			return reasonNewPlacement
		}
		return ""
	}
	return reasonNewUnsupported
}

// packageDeclRE matches a Java or Kotlin package declaration.
var packageDeclRE = regexp.MustCompile(`(?m)^\s*package\s+([\w.]+)\s*;?\s*$`)

// checkNewFilePackage refuses a NEW Java/Kotlin file whose package is not the
// one its directory implies: every file that imports the class by the
// directory's package would fail to find it. Only judged for new files (empty
// original); an existing file's package is not this patch's doing.
func checkNewFilePackage(p, original, patched string) *patchViolation {
	if original != "" {
		return nil
	}
	switch strings.ToLower(path.Ext(p)) {
	case ".java", ".kt":
	default:
		return nil
	}
	want := expectedPackage(filepath.ToSlash(p))
	if want == "" {
		return nil
	}
	got := ""
	if m := packageDeclRE.FindStringSubmatch(patched); m != nil {
		got = m[1]
	}
	if got == want {
		return nil
	}
	return &patchViolation{
		Rule: "new-file-package",
		Detail: fmt.Sprintf("the new file %s must declare `package %s;` to match its directory "+
			"(found %q).", p, want, got),
	}
}

// expectedPackage is the package a source path's directory implies: the
// segments between src/<set>/java|kotlin/ and the file name.
func expectedPackage(rel string) string {
	parts := strings.Split(rel, "/")
	for i := len(parts) - 1; i >= 2; i-- {
		if (parts[i] == "java" || parts[i] == "kotlin") && parts[i-2] == "src" {
			return strings.Join(parts[i+1:len(parts)-1], ".")
		}
	}
	return ""
}
