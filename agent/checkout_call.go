package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RunCheckoutCall runs one autofix tool call against the checkout at root.
// content is the tool output. An error is reported back to Appknox as a failed
// result; unknown tools fail the same way so the job does not wait forever.
func RunCheckoutCall(root, name string, args map[string]interface{}) (string, error) {
	switch name {
	case "read_file":
		return readCheckoutFile(root, strArg(args, "path"))
	case "grep":
		return grepCheckout(root, strArg(args, "pattern"))
	case "glob":
		return globCheckout(root, strArg(args, "pattern")), nil
	case "edit", "str_replace":
		return editCheckoutFile(root, strArg(args, "path"), strArg(args, "old_string"), strArg(args, "new_string"))
	case "create_file":
		return createCheckoutFile(root, strArg(args, "path"), strArg(args, "content"))
	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
}

func strArg(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	s, _ := args[key].(string)
	return s
}

func readCheckoutFile(root, rel string) (string, error) {
	abs, err := resolveUnderRoot(root, rel)
	if err != nil {
		return "", err
	}
	data, truncated, err := readCapped(abs, maxReadBytes)
	if err != nil {
		return "", fmt.Errorf("read_file %q: %w", rel, err)
	}
	text := string(data)
	if truncated {
		text += fmt.Sprintf("\n…[truncated at %d bytes]", maxReadBytes)
	}
	return text, nil
}

func grepCheckout(root, pattern string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("grep pattern: %w", err)
	}
	out, truncated := grepFiles(root, re)
	if len(out) == 0 {
		return "No matches.", nil
	}
	return joinCapped(out, truncated), nil
}

func globCheckout(root, pattern string) string {
	var out []string
	truncated := false
	walkSourceFiles(root, func(rel, _ string) error {
		if globMatches(pattern, rel) {
			out = append(out, rel)
			if len(out) >= maxMatches {
				truncated = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	if len(out) == 0 {
		return "No files matched."
	}
	return joinCapped(out, truncated)
}

func editCheckoutFile(root, rel, oldString, newString string) (string, error) {
	if oldString == "" {
		return "", fmt.Errorf("edit %q: old_string is empty", rel)
	}
	abs, err := resolveUnderRoot(root, rel)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	content := string(data)
	switch strings.Count(content, oldString) {
	case 0:
		return "", fmt.Errorf("old_string not found in %s", rel)
	case 1:
	default:
		return "", fmt.Errorf("old_string is not unique in %s", rel)
	}
	updated := strings.Replace(content, oldString, newString, 1)
	if err := os.WriteFile(abs, []byte(updated), 0o644); err != nil {
		return "", err
	}
	return "edited " + cleanRel(rel), nil
}

func createCheckoutFile(root, rel, content string) (string, error) {
	abs, err := resolveUnderRoot(root, rel)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(abs); err == nil {
		return "", fmt.Errorf("create_file %q: file already exists", rel)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		return "", err
	}
	return "created " + cleanRel(rel), nil
}
