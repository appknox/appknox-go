package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadable_SourceAndBuildFilesOnly(t *testing.T) {
	for _, rel := range []string{
		"app/src/main/java/com/acme/Login.java",
		"app/src/main/AndroidManifest.xml",
		"app/src/main/res/xml/network_security_config.xml",
		"app/build.gradle",
		"app/proguard-rules.pro",
		"gradle/libs.versions.toml",
		"gradle.properties",
		"ios/App/Info.plist",
		"app/src/main/java/com/acme/TokenManager.java",
	} {
		if !readable(rel) {
			t.Errorf("readable(%q) = false, want true", rel)
		}
	}
}

func TestReadable_RefusesHiddenAndCredentialFiles(t *testing.T) {
	for _, rel := range []string{
		".env",
		".github/workflows/ci.yml",
		"app/.secrets/keys.xml",
		"local.properties",
		"keystore.properties",
		"app/google-services.json",
		"ios/App/GoogleService-Info.plist",
		"app/release.jks",
		"app/upload.keystore",
		"app/src/main/res/values/secrets.xml",
		"app/src/main/res/values/api_keys.xml",
		"README.md",
		"config.json",
	} {
		if readable(rel) {
			t.Errorf("readable(%q) = true, want false", rel)
		}
	}
}

func TestReadFile_RefusesCredentialFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "local.properties"), []byte("storePassword=hunter2"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readFile(root, "local.properties")
	if err == nil || !strings.Contains(err.Error(), "not readable by autofix") {
		t.Fatalf("read_file local.properties: err = %v, want a refusal", err)
	}
}

func TestReadFile_RefusesASymlinkToACredentialFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "local.properties"), []byte("storePassword=hunter2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "local.properties"), filepath.Join(root, "Config.java")); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
	if _, err := readFile(root, "Config.java"); err == nil {
		t.Fatal("read_file through a symlink to local.properties succeeded")
	}
}

func TestWalkSourceFiles_SkipsCredentialFiles(t *testing.T) {
	root := t.TempDir()
	values := filepath.Join(root, "app", "src", "main", "res", "values")
	if err := os.MkdirAll(values, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"strings.xml", "secrets.xml"} {
		if err := os.WriteFile(filepath.Join(values, name), []byte("<resources/>"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var seen []string
	walkSourceFiles(root, func(rel, _ string) error {
		seen = append(seen, filepath.Base(rel))
		return nil
	})
	if len(seen) != 1 || seen[0] != "strings.xml" {
		t.Fatalf("walked %v, want only strings.xml", seen)
	}
}
