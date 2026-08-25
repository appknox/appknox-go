package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

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
