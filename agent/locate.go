// Package agent runs a native, read-only file-location agent inside the CLI.
//
// The model plans and calls local read-only tools (read_file, grep, glob) over
// the checked-out repository and returns the single source file to fix. Only the
// model turns leave the machine, and they are routed through the Appknox gateway
// (BaseURL + a scoped session token, never a provider key), which injects the
// server-held provider key. No file is edited here — the fix stays server-side.
package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

const (
	defaultMaxTokens     = 1024
	defaultMaxIterations = 15
)

const locateSystemPrompt = "You are a security code-locating assistant. A SAST scan flagged a " +
	"vulnerability in a repository checked out on disk. Use the read_file, grep and glob tools " +
	"(read-only) to find the SINGLE source file that contains the flagged class/symbol and the " +
	"vulnerable code. Never edit anything. When found, reply with ONLY the repository-relative " +
	"path of that file and nothing else. If you cannot confidently identify it, reply with exactly NONE."

// Config carries the gateway endpoint and the scoped token (not a provider key).
type Config struct {
	FixURL        string // hosted fix-service base, e.g. http://localhost:8100
	Token         string // scoped session/fix token used as the gateway credential
	Model         string // optional; defaults to Claude Sonnet
	MaxTokens     int64  // optional; defaults to defaultMaxTokens
	MaxIterations int    // optional; defaults to defaultMaxIterations
}

// Request describes what to locate in the checkout.
type Request struct {
	RepoRoot  string // absolute or relative path to the checked-out repo
	ClassHint string // class/symbol hint parsed from the finding
	Finding   string // raw finding detail
}

// locateRunner runs the LLM tool-use loop and returns the model's final text.
// It is a seam so the pure locate/validate logic can be tested without network.
type locateRunner func(ctx context.Context, cfg Config, req Request) (string, error)

// LocateFile returns the repository-relative path of the file to fix, or "" when
// the agent abstains (the caller then falls back to a deterministic locate).
func LocateFile(ctx context.Context, cfg Config, req Request) (string, error) {
	return locateWith(ctx, cfg, req, sdkLocate)
}

// locateWith runs the given runner, then validates its answer against the disk.
func locateWith(ctx context.Context, cfg Config, req Request, run locateRunner) (string, error) {
	text, err := run(ctx, cfg, req)
	if err != nil {
		return "", err
	}
	return extractLocatedPath(text, req.RepoRoot), nil
}

// sdkLocate drives the anthropic-sdk-go Tool Runner through the gateway.
func sdkLocate(ctx context.Context, cfg Config, req Request) (string, error) {
	if cfg.FixURL == "" || cfg.Token == "" {
		return "", errors.New("agent: FixURL and Token are required to reach the gateway")
	}
	tools, err := buildLocateTools(req.RepoRoot)
	if err != nil {
		return "", err
	}
	client := anthropic.NewClient(
		option.WithBaseURL(strings.TrimRight(cfg.FixURL, "/")+"/anthropic"),
		option.WithAPIKey(cfg.Token), // scoped gateway token (like ANTHROPIC_API_KEY), NOT a provider key
	)
	runner := client.Beta.Messages.NewToolRunner(tools, locateParams(cfg, req))
	final, err := runner.RunToCompletion(ctx)
	if err != nil {
		return "", err
	}
	return extractText(final), nil
}

// locateParams builds the Tool Runner params (model, prompts, iteration cap).
func locateParams(cfg Config, req Request) anthropic.BetaToolRunnerParams {
	model := cfg.Model
	if model == "" {
		model = string(anthropic.ModelClaudeSonnet5)
	}
	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}
	maxIter := cfg.MaxIterations
	if maxIter <= 0 {
		maxIter = defaultMaxIterations
	}
	return anthropic.BetaToolRunnerParams{
		BetaMessageNewParams: anthropic.BetaMessageNewParams{
			Model:     anthropic.Model(model),
			MaxTokens: maxTokens,
			System:    []anthropic.BetaTextBlockParam{{Text: locateSystemPrompt}},
			Messages: []anthropic.BetaMessageParam{
				anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(locateUserPrompt(req))),
			},
		},
		MaxIterations: maxIter,
	}
}

// locateUserPrompt renders the per-finding instruction.
func locateUserPrompt(req Request) string {
	return fmt.Sprintf(
		"Vulnerable class/symbol (from the scan): %s\nScan finding detail: %s\n\n"+
			"Find the one source file to fix and reply with only its repository-relative path "+
			"(e.g. app/src/main/java/com/appknox/mfva/MainActivity.java), or exactly NONE.",
		req.ClassHint, req.Finding,
	)
}
