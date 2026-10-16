package helper

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
)

// resolvedAutofixFile is the upload EnsureAutofixFile chose.
type resolvedAutofixFile struct {
	FileID      int
	ProjectID   int
	PackageName string
	Platform    string // "android" or "ios"
	Branch      string
}

// projectFileAPI is the slice of the Appknox API the latest-file lookup uses.
type projectFileAPI interface {
	ListProjects(ctx context.Context, opt *appknox.ProjectListOptions) ([]*appknox.Project, error)
	ListFiles(ctx context.Context, projectID int, opt *appknox.FileListOptions) ([]*appknox.File, error)
}

type clientProjectAPI struct {
	client *appknox.Client
}

func (a clientProjectAPI) ListProjects(ctx context.Context, opt *appknox.ProjectListOptions) ([]*appknox.Project, error) {
	if a.client == nil {
		return nil, errors.New("autofix file lookup failed: missing Appknox client")
	}
	projects, _, err := a.client.Projects.List(ctx, opt)
	return projects, err
}

func (a clientProjectAPI) ListFiles(ctx context.Context, projectID int, opt *appknox.FileListOptions) ([]*appknox.File, error) {
	if a.client == nil {
		return nil, errors.New("autofix file lookup failed: missing Appknox client")
	}
	files, _, err := a.client.Files.ListByProject(ctx, projectID, opt)
	return files, err
}

// EnsureAutofixFile sets FileID to the latest upload on the base branch when
// the caller did not pass one and is not using the manual --finding path.
// An explicit --file-id is left unchanged.
func EnsureAutofixFile(ctx context.Context, opts AutofixOptions) (AutofixOptions, error) {
	if opts.FileID > 0 || strings.TrimSpace(opts.Finding) != "" {
		return opts, nil
	}
	resolved, err := resolveLatestAutofixFile(ctx, clientProjectAPI{getClient()}, opts)
	if err != nil {
		return opts, err
	}
	opts.FileID = resolved.FileID
	fmt.Printf("Using latest Appknox file %d on %s (%s, %s)\n", resolved.FileID, resolved.Branch, resolved.PackageName, resolved.Platform)
	return opts, nil
}

func resolveLatestAutofixFile(ctx context.Context, api projectFileAPI, opts AutofixOptions) (resolvedAutofixFile, error) {
	opts = applyCIDefaults(opts)
	branch := strings.TrimSpace(opts.Ref)
	if branch == "" {
		return resolvedAutofixFile{}, errors.New("autofix needs the base branch to find the latest file (--ref, or GITHUB_BASE_REF / GITHUB_REF)")
	}
	id, err := chooseAppIdentity(opts)
	if err != nil {
		return resolvedAutofixFile{}, err
	}
	opt := &appknox.ProjectListOptions{
		PackageName: id.PackageName,
		ListOptions: appknox.ListOptions{Limit: 10},
	}
	if id.Platform != "" {
		_, apiPlatform, err := normalizePlatform(id.Platform)
		if err != nil {
			return resolvedAutofixFile{}, err
		}
		opt.Platform = apiPlatform
	}
	projects, err := api.ListProjects(ctx, opt)
	if err != nil {
		return resolvedAutofixFile{}, fmt.Errorf("lookup Appknox project for %s: %w", id.PackageName, err)
	}
	if len(projects) == 0 {
		label := id.Platform
		if label == "" {
			label = "any platform"
		}
		return resolvedAutofixFile{}, fmt.Errorf("no Appknox project for %s (%s); upload a build of this app first", id.PackageName, label)
	}
	if len(projects) > 1 {
		return resolvedAutofixFile{}, fmt.Errorf("multiple Appknox projects for %s; pass --platform or --file-id", id.PackageName)
	}
	project := projects[0]
	if project == nil || project.ID <= 0 {
		return resolvedAutofixFile{}, fmt.Errorf("Appknox project for %s has no id", id.PackageName)
	}
	// File ids increase on every upload. Mycroft lists a project's files by
	// -id and applies git_branch before pagination, so the first page is the
	// latest builds recorded for this branch.
	files, err := api.ListFiles(ctx, project.ID, &appknox.FileListOptions{
		GitBranch:   branch,
		ListOptions: appknox.ListOptions{Limit: 20},
	})
	if err != nil {
		return resolvedAutofixFile{}, fmt.Errorf("list files for Appknox project %d: %w", project.ID, err)
	}
	newest := newestFile(files)
	if newest == nil {
		return resolvedAutofixFile{}, fmt.Errorf("no file uploaded on branch %s for %s; upload a build on that branch first", branch, id.PackageName)
	}
	label := id.Platform
	if label == "" {
		label = platformLabel(project.Platform)
	}
	return resolvedAutofixFile{
		FileID:      newest.ID,
		ProjectID:   project.ID,
		PackageName: id.PackageName,
		Platform:    label,
		Branch:      branch,
	}, nil
}

func newestFile(files []*appknox.File) *appknox.File {
	var best *appknox.File
	for _, f := range files {
		if f == nil || f.ID <= 0 {
			continue
		}
		if best == nil || f.ID > best.ID {
			best = f
		}
	}
	return best
}

func platformLabel(p enums.PlatformType) string {
	switch p {
	case enums.Platform.Andriod:
		return "android"
	case enums.Platform.IOS:
		return "ios"
	default:
		if s := p.String(); s != "" {
			return s
		}
		return "unknown"
	}
}

// normalizePlatform accepts the flag values and the API's numeric codes.
func normalizePlatform(p string) (label, api string, err error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "android", "andriod", "0":
		return "android", "0", nil
	case "ios", "1":
		return "ios", "1", nil
	default:
		return "", "", fmt.Errorf("--platform %q must be android or ios", p)
	}
}

type appIdentity struct {
	PackageName string
	Platform    string // "android" or "ios"
}

func chooseAppIdentity(opts AutofixOptions) (appIdentity, error) {
	wantPkg := strings.TrimSpace(opts.PackageName)
	wantLabel := ""
	if p := strings.TrimSpace(opts.Platform); p != "" {
		label, _, err := normalizePlatform(p)
		if err != nil {
			return appIdentity{}, err
		}
		wantLabel = label
	}
	if wantPkg != "" && wantLabel != "" {
		return appIdentity{PackageName: wantPkg, Platform: wantLabel}, nil
	}

	root := opts.RepoPath
	if root == "" {
		root = "."
	}
	found, err := detectAppIdentities(root)
	if err != nil {
		return appIdentity{}, err
	}
	var matched []appIdentity
	for _, id := range found {
		if wantPkg != "" && !strings.EqualFold(id.PackageName, wantPkg) {
			continue
		}
		if wantLabel != "" && id.Platform != wantLabel {
			continue
		}
		matched = append(matched, id)
	}
	// A package name with no checkout match still goes to the API, which
	// distinguishes one project from several.
	if wantPkg != "" && wantLabel == "" && len(matched) == 0 {
		return appIdentity{PackageName: wantPkg}, nil
	}
	switch len(matched) {
	case 1:
		return matched[0], nil
	case 0:
		return appIdentity{}, fmt.Errorf("could not find an Android applicationId or iOS bundle id in %s; pass --package-name and --platform", root)
	default:
		return appIdentity{}, fmt.Errorf("found more than one app in %s (%s); pass --platform or --package-name", root, formatIdentities(matched))
	}
}

func formatIdentities(ids []appIdentity) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = id.Platform + " " + id.PackageName
	}
	return strings.Join(parts, ", ")
}

type gradleHit struct {
	id        string
	preferred bool
	inDefault bool
}

var (
	applicationIDRe = regexp.MustCompile(`(?m)\bapplicationId\s*(?:=\s*)?["']([^"']+)["']`)
	manifestPackage = regexp.MustCompile(`(?s)<manifest\b[^>]*?\spackage\s*=\s*"([^"]+)"`)
	bundleIDRe      = regexp.MustCompile(`PRODUCT_BUNDLE_IDENTIFIER\s*=\s*"?([^";]+)"?\s*;`)
	plistBundleRe   = regexp.MustCompile(`(?s)<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>`)
)

const maxIdentityFile = 2 << 20

func detectAppIdentities(root string) ([]appIdentity, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("checkout %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("checkout %s is not a directory", root)
	}
	var hits []gradleHit
	var manifests []string
	var bundles []string
	var plists []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && skipIdentityDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch name := d.Name(); {
		case name == "build.gradle" || name == "build.gradle.kts":
			found, err := gradleApplicationIDs(path)
			if err != nil {
				return err
			}
			hits = append(hits, found...)
		case name == "AndroidManifest.xml" && strings.HasSuffix(filepath.ToSlash(path), "/src/main/AndroidManifest.xml"):
			id, err := manifestPackageName(path)
			if err != nil {
				return err
			}
			if id != "" {
				manifests = append(manifests, id)
			}
		case strings.HasSuffix(name, ".pbxproj"):
			found, err := pbxprojBundleIDs(path)
			if err != nil {
				return err
			}
			bundles = append(bundles, found...)
		case name == "Info.plist":
			id, err := plistBundleID(path)
			if err != nil {
				return err
			}
			if id != "" {
				plists = append(plists, id)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var ids []appIdentity
	for _, pkg := range androidPackages(hits, manifests) {
		ids = append(ids, appIdentity{PackageName: pkg, Platform: "android"})
	}
	iosIDs := withoutTestBundles(bundles)
	if len(iosIDs) == 0 {
		iosIDs = withoutTestBundles(plists)
	}
	for _, pkg := range iosIDs {
		ids = append(ids, appIdentity{PackageName: pkg, Platform: "ios"})
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].Platform == ids[j].Platform {
			return ids[i].PackageName < ids[j].PackageName
		}
		return ids[i].Platform < ids[j].Platform
	})
	return ids, nil
}

func androidPackages(hits []gradleHit, manifests []string) []string {
	var preferredDefault, anyDefault, preferred, all []string
	for _, h := range hits {
		all = append(all, h.id)
		if h.preferred {
			preferred = append(preferred, h.id)
		}
		if h.inDefault {
			anyDefault = append(anyDefault, h.id)
			if h.preferred {
				preferredDefault = append(preferredDefault, h.id)
			}
		}
	}
	for _, set := range [][]string{preferredDefault, anyDefault, preferred, all} {
		if u := uniqueStrings(set); len(u) > 0 {
			return u
		}
	}
	return uniqueStrings(manifests)
}

func skipIdentityDir(name string) bool {
	switch name {
	case ".git", "build", "node_modules", "Pods", ".gradle", "DerivedData", "vendor", ".idea", "intermediates", ".dart_tool":
		return true
	default:
		return false
	}
}

func gradleApplicationIDs(path string) ([]gradleHit, error) {
	text, err := readIdentityFile(path)
	if err != nil || text == "" {
		return nil, err
	}
	preferred := preferredGradle(path)
	var hits []gradleHit
	seenDefault := map[string]bool{}
	for _, body := range defaultConfigBodies(text) {
		for _, id := range applicationIDs(body) {
			seenDefault[id] = true
			hits = append(hits, gradleHit{id: id, preferred: preferred, inDefault: true})
		}
	}
	for _, id := range applicationIDs(text) {
		if seenDefault[id] {
			continue
		}
		hits = append(hits, gradleHit{id: id, preferred: preferred})
	}
	return hits, nil
}

func preferredGradle(path string) bool {
	p := filepath.ToSlash(path)
	return strings.HasSuffix(p, "app/build.gradle") || strings.HasSuffix(p, "app/build.gradle.kts")
}

func defaultConfigBodies(src string) []string {
	var bodies []string
	rest := src
	for {
		i := strings.Index(rest, "defaultConfig")
		if i < 0 {
			return bodies
		}
		rest = rest[i+len("defaultConfig"):]
		brace := strings.Index(rest, "{")
		if brace < 0 || brace > 80 {
			continue
		}
		body, ok := braceBody(rest[brace:])
		if !ok {
			return bodies
		}
		bodies = append(bodies, body)
		rest = rest[brace+len(body):]
	}
}

func braceBody(src string) (string, bool) {
	if !strings.HasPrefix(src, "{") {
		return "", false
	}
	depth := 0
	for i, r := range src {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[:i+1], true
			}
		}
	}
	return "", false
}

func applicationIDs(src string) []string {
	var ids []string
	for _, m := range applicationIDRe.FindAllStringSubmatch(src, -1) {
		if id := cleanIdentity(m[1]); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func manifestPackageName(path string) (string, error) {
	text, err := readIdentityFile(path)
	if err != nil || text == "" {
		return "", err
	}
	m := manifestPackage.FindStringSubmatch(text)
	if m == nil {
		return "", nil
	}
	return cleanIdentity(m[1]), nil
}

func pbxprojBundleIDs(path string) ([]string, error) {
	text, err := readIdentityFile(path)
	if err != nil || text == "" {
		return nil, err
	}
	var ids []string
	for _, m := range bundleIDRe.FindAllStringSubmatch(text, -1) {
		if id := cleanIdentity(m[1]); id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func plistBundleID(path string) (string, error) {
	text, err := readIdentityFile(path)
	if err != nil || text == "" {
		return "", err
	}
	m := plistBundleRe.FindStringSubmatch(text)
	if m == nil {
		return "", nil
	}
	return cleanIdentity(m[1]), nil
}

func cleanIdentity(id string) string {
	id = strings.Trim(strings.TrimSpace(id), `"'`)
	if id == "" || strings.Contains(id, "$") || strings.ContainsAny(id, " \t") {
		return ""
	}
	return id
}

func withoutTestBundles(ids []string) []string {
	var keep []string
	for _, id := range ids {
		if !testBundle(id) {
			keep = append(keep, id)
		}
	}
	if len(keep) == 0 {
		return uniqueStrings(ids)
	}
	return uniqueStrings(keep)
}

func testBundle(id string) bool {
	last := id
	if i := strings.LastIndex(id, "."); i >= 0 {
		last = id[i+1:]
	}
	return strings.Contains(strings.ToLower(last), "test")
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func readIdentityFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Size() > maxIdentityFile {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
