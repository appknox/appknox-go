package agent

import "fmt"

// ExecTool runs one Sherrinford tool call against the checkout.
// allowed is the only path edit and create_file may touch. Empty allowed
// refuses both, which is a locate turn.
func ExecTool(root, name string, args map[string]any, allowed string) (string, error) {
	switch name {
	case "read_file":
		return readFile(root, argString(args, "path"))
	case "grep":
		return grep(root, argString(args, "pattern"))
	case "glob":
		return glob(root, argString(args, "pattern"))
	case "edit":
		if allowed == "" {
			return "", fmt.Errorf("agent: edit is not available on a locate turn")
		}
		return editFile(root, allowed, argString(args, "path"),
			argString(args, "old_string"), argString(args, "new_string"))
	case "create_file":
		if allowed == "" {
			return "", fmt.Errorf("agent: create_file is not available on a locate turn")
		}
		return createFile(root, allowed, argString(args, "path"), argString(args, "content"))
	default:
		return "", fmt.Errorf("agent: unknown tool %q", name)
	}
}

func argString(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	s, _ := args[key].(string)
	return s
}
