package helper

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// ciCheckPolicyFileName is the small JSON state file cicheck writes so a
// later `autofix --file-id <id>` run on the same file can inherit cicheck's
// severity policy without the operator passing --risk-threshold twice.
const ciCheckPolicyFileName = "cicheck-policy.json"

// RecordCiCheckPolicy merges {"<fileID>": thresholdName} into
// <configDir>/cicheck-policy.json, creating the file and configDir if
// needed. It writes atomically (temp file + rename) with a 0600 file mode
// and a 0700 directory mode, and never overwrites entries for other file
// ids already recorded there.
//
// The caller (cmd/cicheck.go) treats any error from this as a warning, never
// a reason to fail cicheck itself -- this state exists purely as a
// convenience for a later autofix run.
func RecordCiCheckPolicy(configDir string, fileID int, thresholdName string) error {
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return fmt.Errorf("cicheck-policy: create config dir: %w", err)
	}
	path := filepath.Join(configDir, ciCheckPolicyFileName)

	existing, err := readPolicyFile(path)
	if err != nil {
		return fmt.Errorf("cicheck-policy: read existing state: %w", err)
	}
	existing[strconv.Itoa(fileID)] = thresholdName

	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("cicheck-policy: encode: %w", err)
	}
	return writePolicyFileAtomically(configDir, path, data)
}

// writePolicyFileAtomically writes data to path via a temp file in the same
// directory plus a rename, so a reader never observes a partially written
// file.
func writePolicyFileAtomically(configDir, path string, data []byte) error {
	tmp, err := os.CreateTemp(configDir, "cicheck-policy-*.json.tmp")
	if err != nil {
		return fmt.Errorf("cicheck-policy: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("cicheck-policy: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cicheck-policy: close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("cicheck-policy: chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("cicheck-policy: rename into place: %w", err)
	}
	return nil
}

// readPolicyFile reads the cicheck-policy.json map at path. A missing file
// reads as an empty map, not an error -- there is simply nothing recorded
// yet. Invalid JSON is returned as an error so RecordCiCheckPolicy never
// silently clobbers content it could not parse, and so ReadCiCheckPolicy can
// let its caller decide to warn-and-fall-back instead of failing outright.
func readPolicyFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return map[string]string{}, nil
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}

// ReadCiCheckPolicy returns the risk-threshold name cicheck recorded for
// fileID (found=true), or found=false when nothing is recorded for it -- a
// missing state file and a missing entry both read this way, since neither
// is a failure, just "nothing recorded yet".
//
// A CORRUPT state file (invalid JSON) is different: it returns a non-nil
// error alongside found=false, so a caller (cmd/autofix.go's
// autofixRiskThreshold) can print a warning and fall back rather than
// silently treating a broken file the same as an absent one.
func ReadCiCheckPolicy(configDir string, fileID int) (thresholdName string, found bool, err error) {
	path := filepath.Join(configDir, ciCheckPolicyFileName)
	m, err := readPolicyFile(path)
	if err != nil {
		return "", false, err
	}
	name, ok := m[strconv.Itoa(fileID)]
	return name, ok, nil
}
