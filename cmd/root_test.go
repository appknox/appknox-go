package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// captureStdio redirects os.Stdout and os.Stderr for the duration of f and
// returns what each captured, so a test can assert not just that a message
// was printed, but which stream it went to — the exact distinction behind
// the regression this file guards against (a warning on stdout corrupts any
// CI script that does `file_id=$(./appknox upload ...)`).
func captureStdio(f func()) (stdout, stderr string) {
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr

	f()

	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr

	var bufOut, bufErr bytes.Buffer
	_, _ = io.Copy(&bufOut, rOut)
	_, _ = io.Copy(&bufErr, rErr)
	return bufOut.String(), bufErr.String()
}

func TestDefaultConfigFile(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := defaultConfigFile()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := filepath.Join(homeDir, ".config", "appknox.json")
	if got != want {
		t.Errorf("defaultConfigFile() = %q, want %q", got, want)
	}
}

// TestCreateDefaultConfigFile_MakesWriteConfigWork is the regression test for
// the bug this function exists to fix: previously, the fallback path only
// called os.Create and never told viper the file's path, so a later
// WriteConfig() (from `config set` or `init`) failed with "Config File ...
// Not Found" even once the file existed on disk. On Windows the same
// function's caller also mis-resolved the search path entirely — see
// defaultConfigFile's doc comment — but this failure mode is not
// platform-specific: it reproduces here regardless of OS.
func TestCreateDefaultConfigFile_MakesWriteConfigWork(t *testing.T) {
	oldConfigFile := viper.ConfigFileUsed()
	defer viper.SetConfigFile(oldConfigFile)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "nested", "appknox.json")

	if err := createDefaultConfigFile(configFile); err != nil {
		t.Fatalf("createDefaultConfigFile returned error: %v", err)
	}

	if _, err := os.Stat(configFile); err != nil {
		t.Fatalf("expected config file to exist: %v", err)
	}

	if viper.ConfigFileUsed() != configFile {
		t.Fatalf("viper.ConfigFileUsed() = %q, want %q — WriteConfig would fail without this being set", viper.ConfigFileUsed(), configFile)
	}

	viper.Set("include-needs-review", true)
	if err := viper.WriteConfig(); err != nil {
		t.Fatalf("WriteConfig() returned error: %v — this is the exact bug being fixed", err)
	}
}

// TestCreateDefaultConfigFile_WritesReadableConfig is the regression test for
// the self-perpetuating "recreate" bug: createDefaultConfigFile used to just
// os.Create an empty file. An empty file is never valid JSON, so the very
// next command's ReadInConfig() would fail again, re-triggering the same
// "recreate" path forever — every future invocation, permanently, once
// triggered once. The recreated file must round-trip through a fresh
// ReadInConfig() without error.
func TestCreateDefaultConfigFile_WritesReadableConfig(t *testing.T) {
	oldConfigFile := viper.ConfigFileUsed()
	defer viper.SetConfigFile(oldConfigFile)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "appknox.json")

	if err := createDefaultConfigFile(configFile); err != nil {
		t.Fatalf("createDefaultConfigFile returned error: %v", err)
	}

	fresh := viper.New()
	fresh.SetConfigFile(configFile)
	if err := fresh.ReadInConfig(); err != nil {
		t.Fatalf("a freshly (re)created config file must be readable, got: %v — "+
			"this means every future command will hit the same recreate path forever", err)
	}
}

// TestWarnAndRecreateConfigFile_WarningGoesToStderr is the regression test
// for the CI-breaking bug: the warning printed when an existing config file
// can't be read must never land on stdout, since CI scripts commonly do
// `file_id=$(./appknox upload ...)` — anything on stdout becomes part of the
// captured value and corrupts it.
func TestWarnAndRecreateConfigFile_WarningGoesToStderr(t *testing.T) {
	oldConfigFile := viper.ConfigFileUsed()
	defer viper.SetConfigFile(oldConfigFile)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "appknox.json")
	// Simulate a pre-existing, unreadable (empty/corrupt) config file.
	if err := os.WriteFile(configFile, nil, 0o600); err != nil {
		t.Fatalf("failed to seed corrupt config file: %v", err)
	}

	var err error
	stdout, stderr := captureStdio(func() {
		err = warnAndRecreateConfigFile(configFile)
	})

	if err != nil {
		t.Fatalf("warnAndRecreateConfigFile returned error: %v", err)
	}
	if stdout != "" {
		t.Errorf("expected nothing on stdout, got %q — this is exactly what corrupts `$(appknox ...)` in CI", stdout)
	}
	if stderr == "" {
		t.Error("expected a warning on stderr, got none")
	}
}

// TestWarnAndRecreateConfigFile_NoWarningWhenFileAbsent preserves the
// existing (correct) behavior for a machine's first-ever run: no config file
// exists yet, so there's nothing to warn about — only genuinely-broken
// *existing* files should be warned about.
func TestWarnAndRecreateConfigFile_NoWarningWhenFileAbsent(t *testing.T) {
	oldConfigFile := viper.ConfigFileUsed()
	defer viper.SetConfigFile(oldConfigFile)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "nested", "appknox.json")

	stdout, stderr := captureStdio(func() {
		if err := warnAndRecreateConfigFile(configFile); err != nil {
			t.Fatalf("warnAndRecreateConfigFile returned error: %v", err)
		}
	})

	if stdout != "" || stderr != "" {
		t.Errorf("expected no output when no prior file exists, got stdout=%q stderr=%q", stdout, stderr)
	}
}
