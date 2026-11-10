package helper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordCiCheckPolicy_WritesAndMerges(t *testing.T) {
	dir := t.TempDir()

	if err := RecordCiCheckPolicy(dir, 10, "low"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := RecordCiCheckPolicy(dir, 20, "critical"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	path := filepath.Join(dir, "cicheck-policy.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected policy file to exist: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("expected valid JSON, got error %v (%s)", err, data)
	}
	if m["10"] != "low" || m["20"] != "critical" {
		t.Fatalf("want both file ids recorded, got %v", m)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("want file mode 0600, got %o", info.Mode().Perm())
	}
}

func TestRecordCiCheckPolicy_CreatesConfigDirWithRestrictedPerms(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "nested-config")

	if err := RecordCiCheckPolicy(dir, 1, "low"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("want config dir mode 0700, got %o", info.Mode().Perm())
	}
}

func TestReadCiCheckPolicy_ReturnsRecordedValueForFileID(t *testing.T) {
	dir := t.TempDir()
	if err := RecordCiCheckPolicy(dir, 77, "critical"); err != nil {
		t.Fatal(err)
	}
	if err := RecordCiCheckPolicy(dir, 78, "low"); err != nil {
		t.Fatal(err)
	}

	name, found, err := ReadCiCheckPolicy(dir, 77)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || name != "critical" {
		t.Fatalf("want (\"critical\", true), got (%q, %v)", name, found)
	}

	_, found, err = ReadCiCheckPolicy(dir, 999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("want found=false for an unrecorded file id")
	}
}

func TestReadCiCheckPolicy_MissingFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()

	_, found, err := ReadCiCheckPolicy(dir, 1)
	if err != nil {
		t.Fatalf("a missing state file must not be an error, got: %v", err)
	}
	if found {
		t.Fatal("want found=false when no state file exists")
	}
}

func TestReadCiCheckPolicy_CorruptFileReturnsErrorNotFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cicheck-policy.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, found, err := ReadCiCheckPolicy(dir, 1)
	if err == nil {
		t.Fatal("want an error for a corrupt state file, so the caller can warn instead of guessing")
	}
	if found {
		t.Fatal("want found=false when the state file is corrupt")
	}
}
