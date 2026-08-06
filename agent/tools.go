package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/toolrunner"
)

// Tool input schemas (invopop/jsonschema tags drive the tool definition).
type readFileInput struct {
	Path string `json:"path" jsonschema:"required,description=Repository-relative path of the source file to read"`
}

type grepInput struct {
	Pattern string `json:"pattern" jsonschema:"required,description=Go regular expression to search for across source files"`
}

type globInput struct {
	Pattern string `json:"pattern" jsonschema:"required,description=Glob matched against each file basename and repo-relative path (e.g. *MainActivity*.java)"`
}

// textResult wraps a plain-text tool result.
func textResult(s string) anthropic.BetaToolResultBlockParamContentUnion {
	return anthropic.BetaToolResultBlockParamContentUnion{OfText: &anthropic.BetaTextBlockParam{Text: s}}
}

// readFileHandler returns a read_file handler scoped to root (CWE-22 guarded).
func readFileHandler(root string) func(context.Context, readFileInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
	return func(_ context.Context, in readFileInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
		abs, err := resolveUnderRoot(root, in.Path)
		if err != nil {
			return anthropic.BetaToolResultBlockParamContentUnion{}, err
		}
		data, truncated, err := readCapped(abs, maxReadBytes)
		if err != nil {
			return anthropic.BetaToolResultBlockParamContentUnion{}, fmt.Errorf("agent: read_file %q: %w", in.Path, err)
		}
		text := string(data)
		if truncated {
			text += fmt.Sprintf("\n…[truncated at %d bytes]", maxReadBytes)
		}
		return textResult(text), nil
	}
}

// grepHandler returns a grep handler that scans real source files under root.
func grepHandler(root string) func(context.Context, grepInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
	return func(_ context.Context, in grepInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
		re, err := regexp.Compile(in.Pattern)
		if err != nil {
			return anthropic.BetaToolResultBlockParamContentUnion{}, fmt.Errorf("agent: grep pattern: %w", err)
		}
		out, truncated := grepFiles(root, re)
		if len(out) == 0 {
			return textResult("No matches."), nil
		}
		return textResult(joinCapped(out, truncated)), nil
	}
}

// grepFiles walks source files under root collecting up to maxMatches "path:line"
// hits, skipping oversized files without reading them whole.
func grepFiles(root string, re *regexp.Regexp) ([]string, bool) {
	var out []string
	truncated := false
	walkSourceFiles(root, func(rel, abs string) error {
		if info, err := os.Stat(abs); err != nil || info.Size() > maxScanBytes {
			return nil
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			if re.MatchString(line) {
				out = append(out, fmt.Sprintf("%s:%d:%s", rel, i+1, strings.TrimSpace(line)))
				if len(out) >= maxMatches {
					truncated = true
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	return out, truncated
}

// globHandler returns a glob handler that lists matching source files under root.
func globHandler(root string) func(context.Context, globInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
	return func(_ context.Context, in globInput) (anthropic.BetaToolResultBlockParamContentUnion, error) {
		var out []string
		truncated := false
		walkSourceFiles(root, func(rel, _ string) error {
			if globMatches(in.Pattern, rel) {
				out = append(out, rel)
				if len(out) >= maxMatches {
					truncated = true
					return filepath.SkipAll
				}
			}
			return nil
		})
		if len(out) == 0 {
			return textResult("No files matched."), nil
		}
		return textResult(joinCapped(out, truncated)), nil
	}
}

// joinCapped renders result lines, appending a marker when the cap was hit.
func joinCapped(lines []string, truncated bool) string {
	text := strings.Join(lines, "\n")
	if truncated {
		text += fmt.Sprintf("\n…[truncated at %d results — narrow the pattern]", maxMatches)
	}
	return text
}

// globMatches reports whether pattern matches the path or its basename.
func globMatches(pattern, rel string) bool {
	if ok, _ := filepath.Match(pattern, rel); ok {
		return true
	}
	ok, _ := filepath.Match(pattern, filepath.Base(rel))
	return ok
}

// buildLocateTools builds the read-only Read/Grep/Glob tool set scoped to root.
func buildLocateTools(root string) ([]anthropic.BetaTool, error) {
	read, err := toolrunner.NewBetaToolFromJSONSchema(
		"read_file", "Read a source file by repository-relative path.", readFileHandler(root))
	if err != nil {
		return nil, err
	}
	grep, err := toolrunner.NewBetaToolFromJSONSchema(
		"grep", "Search source files for a regular expression; returns path:line matches.", grepHandler(root))
	if err != nil {
		return nil, err
	}
	glob, err := toolrunner.NewBetaToolFromJSONSchema(
		"glob", "List source files whose basename or path matches a glob pattern.", globHandler(root))
	if err != nil {
		return nil, err
	}
	return []anthropic.BetaTool{read, grep, glob}, nil
}
