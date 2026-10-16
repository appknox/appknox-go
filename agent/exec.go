package agent

import (
	"context"
	"fmt"

	sdk "github.com/anthropics/anthropic-sdk-go"
)

// ExecTool runs one Sherrinford tool call against the checkout.
// allowed is the only path edit and create_file may touch. Empty allowed
// refuses both, which is a locate turn.
func ExecTool(root, name string, args map[string]any, allowed string) (string, error) {
	switch name {
	case "read_file":
		res, err := readFileHandler(root)(context.Background(), readFileInput{Path: argString(args, "path")})
		return toolText(res), err
	case "grep":
		res, err := grepHandler(root)(context.Background(), grepInput{Pattern: argString(args, "pattern")})
		return toolText(res), err
	case "glob":
		res, err := globHandler(root)(context.Background(), globInput{Pattern: argString(args, "pattern")})
		return toolText(res), err
	case "edit":
		if allowed == "" {
			return "", fmt.Errorf("agent: edit is not available on a locate turn")
		}
		var edits []editRecord
		res, err := editHandler(root, allowed, &edits)(context.Background(), editInput{
			Path: argString(args, "path"), OldString: argString(args, "old_string"), NewString: argString(args, "new_string"),
		})
		return toolText(res), err
	case "create_file":
		if allowed == "" {
			return "", fmt.Errorf("agent: create_file is not available on a locate turn")
		}
		var edits []editRecord
		res, err := createHandler(root, allowed, &edits)(context.Background(), createInput{
			Path: argString(args, "path"), Content: argString(args, "content"),
		})
		return toolText(res), err
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

func toolText(res sdk.BetaToolResultBlockParamContentUnion) string {
	if res.OfText != nil {
		return res.OfText.Text
	}
	return ""
}
