package helper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/appknox/appknox-go/appknox"
)

type fakeProjectAPI struct {
	projects    []*appknox.Project
	files       map[int][]*appknox.File
	projectsErr error
	filesErr    error
	gotPackage  string
	gotPlatform string
	gotBranch   string
	gotLimit    int
}

func (f *fakeProjectAPI) ListProjects(_ context.Context, opt *appknox.ProjectListOptions) ([]*appknox.Project, error) {
	if opt != nil {
		f.gotPackage = opt.PackageName
		f.gotPlatform = opt.Platform
	}
	if f.projectsErr != nil {
		return nil, f.projectsErr
	}
	return f.projects, nil
}

func (f *fakeProjectAPI) ListFiles(_ context.Context, projectID int, opt *appknox.FileListOptions) ([]*appknox.File, error) {
	if opt != nil {
		f.gotLimit = opt.Limit
		f.gotBranch = opt.GitBranch
	}
	if f.filesErr != nil {
		return nil, f.filesErr
	}
	return f.files[projectID], nil
}

func TestResolveLatest_ExplicitIdentityUsesNewestFile(t *testing.T) {
	api := &fakeProjectAPI{
		projects: []*appknox.Project{{ID: 7, PackageName: "com.appknox.mfva"}},
		files: map[int][]*appknox.File{
			7: {{ID: 10}, {ID: 118}, {ID: 40}},
		},
	}
	got, err := resolveLatestAutofixFile(context.Background(), api, AutofixOptions{
		PackageName: "com.appknox.mfva",
		Platform:    "android",
		RepoPath:    "/does/not/exist",
		Ref:         "master",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.FileID != 118 {
		t.Fatalf("want newest file 118, got %d", got.FileID)
	}
	if api.gotPackage != "com.appknox.mfva" || api.gotPlatform != "0" {
		t.Fatalf("want project query package com.appknox.mfva platform 0, got %q %q", api.gotPackage, api.gotPlatform)
	}
	if got.Platform != "android" || got.ProjectID != 7 || got.Branch != "master" {
		t.Fatalf("want android project 7 on master, got %+v", got)
	}
	if api.gotBranch != "master" {
		t.Fatalf("want file query git_branch master, got %q", api.gotBranch)
	}
}

func TestResolveLatest_NoProject(t *testing.T) {
	api := &fakeProjectAPI{}
	_, err := resolveLatestAutofixFile(context.Background(), api, AutofixOptions{
		PackageName: "com.missing.app",
		Platform:    "ios",
		Ref:         "master",
	})
	if err == nil || !strings.Contains(err.Error(), "no Appknox project") {
		t.Fatalf("want a missing-project error, got %v", err)
	}
}

func TestResolveLatest_NoFiles(t *testing.T) {
	api := &fakeProjectAPI{
		projects: []*appknox.Project{{ID: 3}},
		files:    map[int][]*appknox.File{3: {}},
	}
	_, err := resolveLatestAutofixFile(context.Background(), api, AutofixOptions{
		PackageName: "com.appknox.mfva",
		Platform:    "android",
		Ref:         "master",
	})
	if err == nil || !strings.Contains(err.Error(), "no file uploaded on branch") {
		t.Fatalf("want a no-file error, got %v", err)
	}
}

func TestResolveLatest_MultipleProjects(t *testing.T) {
	api := &fakeProjectAPI{
		projects: []*appknox.Project{{ID: 1}, {ID: 2}},
	}
	_, err := resolveLatestAutofixFile(context.Background(), api, AutofixOptions{
		PackageName: "com.appknox.mfva",
		RepoPath:    t.TempDir(),
		Ref:         "master",
	})
	if err == nil || !strings.Contains(err.Error(), "multiple Appknox projects") {
		t.Fatalf("want a multiple-project error, got %v", err)
	}
}

func TestResolveLatest_InvalidPlatform(t *testing.T) {
	_, err := resolveLatestAutofixFile(context.Background(), &fakeProjectAPI{}, AutofixOptions{
		PackageName: "com.appknox.mfva",
		Platform:    "windows",
		Ref:         "master",
	})
	if err == nil || !strings.Contains(err.Error(), "android or ios") {
		t.Fatalf("want a platform error, got %v", err)
	}
}

func TestResolveLatest_DetectsCheckout(t *testing.T) {
	root := t.TempDir()
	writeIdentityFile(t, root, "app/build.gradle", `android { defaultConfig { applicationId "com.appknox.mfva" } }`)
	api := &fakeProjectAPI{
		projects: []*appknox.Project{{ID: 9, PackageName: "com.appknox.mfva"}},
		files:    map[int][]*appknox.File{9: {{ID: 4}, {ID: 24}}},
	}
	got, err := resolveLatestAutofixFile(context.Background(), api, AutofixOptions{RepoPath: root, Ref: "develop"})
	if err != nil {
		t.Fatal(err)
	}
	if got.FileID != 24 || got.PackageName != "com.appknox.mfva" || got.Platform != "android" {
		t.Fatalf("want file 24 android com.appknox.mfva, got %+v", got)
	}
	if api.gotPlatform != "0" || api.gotPackage != "com.appknox.mfva" || api.gotBranch != "develop" {
		t.Fatalf("want query com.appknox.mfva platform 0 branch develop, got %q %q %q", api.gotPackage, api.gotPlatform, api.gotBranch)
	}
}

func TestResolveLatest_NeedsBaseBranch(t *testing.T) {
	clearCIRepoEnv(t)
	_, err := resolveLatestAutofixFile(context.Background(), &fakeProjectAPI{}, AutofixOptions{
		PackageName: "com.appknox.mfva",
		Platform:    "android",
	})
	if err == nil || !strings.Contains(err.Error(), "base branch") {
		t.Fatalf("want a missing-branch error, got %v", err)
	}
}

func TestResolveLatest_UsesCIBaseBranch(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_BASE_REF", "release/1.2")
	api := &fakeProjectAPI{
		projects: []*appknox.Project{{ID: 7, PackageName: "com.appknox.mfva"}},
		files:    map[int][]*appknox.File{7: {{ID: 9}}},
	}
	got, err := resolveLatestAutofixFile(context.Background(), api, AutofixOptions{
		PackageName: "com.appknox.mfva",
		Platform:    "android",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.FileID != 9 || got.Branch != "release/1.2" || api.gotBranch != "release/1.2" {
		t.Fatalf("want file 9 on release/1.2, got %+v query %q", got, api.gotBranch)
	}
}

func TestFillUploadFromCI_UsesSameBaseBranch(t *testing.T) {
	clearCIRepoEnv(t)
	t.Setenv("GITHUB_REPOSITORY", "appknox/mfva")
	t.Setenv("GITHUB_REF", "refs/heads/develop")

	got := fillUploadFromCI(UploadOptions{KnoxIQ: true})
	if got.GitBranch != "develop" || got.GitRepo != "appknox/mfva" || !got.KnoxIQ {
		t.Fatalf("want develop appknox/mfva knoxiq, got %+v", got)
	}

	explicit := fillUploadFromCI(UploadOptions{GitBranch: "main", GitRepo: "other/app"})
	if explicit.GitBranch != "main" || explicit.GitRepo != "other/app" {
		t.Fatalf("explicit branch and repo must win, got %+v", explicit)
	}
}

func TestDetectAppIdentities_AndroidApplicationIDIgnoresBuildOutput(t *testing.T) {
	root := t.TempDir()
	writeIdentityFile(t, root, "app/build.gradle", `
android {
    defaultConfig {
        applicationId "com.appknox.mfva"
    }
    productFlavors {
        demo { applicationId "com.appknox.mfva.demo" }
    }
}
`)
	writeIdentityFile(t, root, "app/build/intermediates/merged_manifest/release/AndroidManifest.xml",
		`<manifest package="com.wrong.built">`)
	writeIdentityFile(t, root, "app/src/main/AndroidManifest.xml",
		`<manifest package="com.appknox.mfva">`)

	got, err := detectAppIdentities(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PackageName != "com.appknox.mfva" || got[0].Platform != "android" {
		t.Fatalf("want android com.appknox.mfva, got %+v", got)
	}
}

func TestDetectAppIdentities_ManifestWhenGradleHasNoApplicationID(t *testing.T) {
	root := t.TempDir()
	writeIdentityFile(t, root, "app/src/main/AndroidManifest.xml", `
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.appknox.mfva">
</manifest>
`)
	got, err := detectAppIdentities(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PackageName != "com.appknox.mfva" || got[0].Platform != "android" {
		t.Fatalf("want android com.appknox.mfva, got %+v", got)
	}
}

func TestDetectAppIdentities_IOSSkipsTestBundle(t *testing.T) {
	root := t.TempDir()
	writeIdentityFile(t, root, "ios/Runner.xcodeproj/project.pbxproj", `
PRODUCT_BUNDLE_IDENTIFIER = com.example.app;
PRODUCT_BUNDLE_IDENTIFIER = com.example.appTests;
PRODUCT_BUNDLE_IDENTIFIER = "$(PRODUCT_BUNDLE_IDENTIFIER)";
`)
	got, err := detectAppIdentities(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PackageName != "com.example.app" || got[0].Platform != "ios" {
		t.Fatalf("want ios com.example.app, got %+v", got)
	}
}

func TestChooseAppIdentity_BothPlatformsNeedAChoice(t *testing.T) {
	root := t.TempDir()
	writeIdentityFile(t, root, "android/app/build.gradle", `applicationId "com.example.app"`)
	writeIdentityFile(t, root, "ios/Runner.xcodeproj/project.pbxproj", `PRODUCT_BUNDLE_IDENTIFIER = com.example.ios;`)

	_, err := chooseAppIdentity(AutofixOptions{RepoPath: root})
	if err == nil || !strings.Contains(err.Error(), "--platform") {
		t.Fatalf("want a platform choice error, got %v", err)
	}

	got, err := chooseAppIdentity(AutofixOptions{RepoPath: root, Platform: "ios"})
	if err != nil {
		t.Fatal(err)
	}
	if got.PackageName != "com.example.ios" || got.Platform != "ios" {
		t.Fatalf("want ios com.example.ios, got %+v", got)
	}
}

func TestChooseAppIdentity_EmptyCheckout(t *testing.T) {
	root := t.TempDir()
	_, err := chooseAppIdentity(AutofixOptions{RepoPath: root})
	if err == nil || !strings.Contains(err.Error(), "--package-name") {
		t.Fatalf("want a detection error, got %v", err)
	}
}

func writeIdentityFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
