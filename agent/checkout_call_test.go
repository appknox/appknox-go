package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunCheckoutCall_readAndEdit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "app", "A.java")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("class A { int x = 1; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := RunCheckoutCall(root, "read_file", map[string]interface{}{"path": "app/A.java"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "class A { int x = 1; }\n" {
		t.Fatalf("read = %q", got)
	}

	if _, err := RunCheckoutCall(root, "edit", map[string]interface{}{
		"path": "app/A.java", "old_string": "int x = 1;", "new_string": "int x = 2;",
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "class A { int x = 2; }\n" {
		t.Fatalf("edited = %q", data)
	}

	if _, err := RunCheckoutCall(root, "read_file", map[string]interface{}{"path": "../outside"}); err == nil {
		t.Fatal("path escape was accepted")
	}
	if _, err := RunCheckoutCall(root, "no_such_tool", nil); err == nil {
		t.Fatal("unknown tool was accepted")
	}
}
