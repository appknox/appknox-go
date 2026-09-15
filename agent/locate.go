// Package agent runs a native, read-only file-location agent inside the CLI.
//
// The model plans and calls local read-only tools (read_file, grep, glob) over
// the checked-out repository and returns the single source file to fix. Only the
// model turns leave the machine, and they are routed through Mycroft
// ({APPKNOX_API_HOST}/api/knoxiq/autofix/ + a PAT, never a provider key).
// Mycroft forwards to Sherrinford, which injects the server-held provider key.
package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

const (
	autofixMessagesPath     = "/api/knoxiq/autofix/"
	anthropicMessagesSuffix = "/v1/messages"
)

// autofixBaseURL is Mycroft's KnoxIQ autofix proxy on the same API host.
// The Anthropic SDK still appends /v1/messages; rewriteAutofixMessages
// strips that so the POST lands on /api/knoxiq/autofix/.
func autofixBaseURL(host string) string {
	return strings.TrimRight(host, "/") + autofixMessagesPath
}

// rewriteAutofixMessages maps the SDK's /v1/messages path onto Mycroft's
// KnoxIQ proxy. Query strings (e.g. beta=true) are left intact.
func rewriteAutofixMessages(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, anthropicMessagesSuffix) {
		req.URL.Path = strings.TrimSuffix(req.URL.Path, anthropicMessagesSuffix)
		if !strings.HasSuffix(req.URL.Path, "/") {
			req.URL.Path += "/"
		}
	}
	return next(req)
}

func newAutofixSDK(cfg Config) sdk.Client {
	return sdk.NewClient(
		option.WithBaseURL(autofixBaseURL(cfg.Host)),
		option.WithAPIKey(cfg.Token),
		option.WithMiddleware(rewriteAutofixMessages),
	)
}

const (
	defaultMaxTokens     = 1024
	defaultMaxIterations = 15
)

const locateSystemPrompt = "You are a security code-locating assistant. A SAST scan flagged a " +
	"vulnerability in a repository checked out on disk. Use the read_file, grep and glob tools " +
	"(read-only) to find the SINGLE source file that contains the flagged class/symbol and the " +
	"vulnerable code. Never edit anything. When found, reply with ONLY the repository-relative " +
	"path of that file and nothing else. If you cannot confidently identify it, reply with exactly NONE."

// Config uses the same Mycroft API host as every other CLI command.
type Config struct {
	Host          string // APPKNOX_API_HOST; messages go to {Host}/api/knoxiq/autofix/
	Token         string // Appknox PAT presented to Mycroft (not a provider key)
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

// sdkLocate drives the model tool-runner through Mycroft autofix.
func sdkLocate(ctx context.Context, cfg Config, req Request) (string, error) {
	if cfg.Host == "" || cfg.Token == "" {
		return "", errors.New("agent: Host and Token are required to reach Mycroft")
	}
	tools, err := buildLocateTools(req.RepoRoot)
	if err != nil {
		return "", err
	}
	client := newAutofixSDK(cfg)
	runner := client.Beta.Messages.NewToolRunner(tools, locateParams(cfg, req))
	final, err := runner.RunToCompletion(ctx)
	if err != nil {
		return "", err
	}
	return extractText(final), nil
}

// locateParams builds the Tool Runner params for the locate pass.
func locateParams(cfg Config, req Request) sdk.BetaToolRunnerParams {
	return runnerParams(cfg, locateSystemPrompt, locateUserPrompt(req))
}

// runnerParams builds Tool Runner params with cfg's model/token/iteration
// defaults and the given system + user prompts. Shared by locate and fix.
func runnerParams(cfg Config, system, user string) sdk.BetaToolRunnerParams {
	model := cfg.Model
	if model == "" {
		model = string(sdk.ModelClaudeSonnet5)
	}
	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}
	maxIter := cfg.MaxIterations
	if maxIter <= 0 {
		maxIter = defaultMaxIterations
	}
	return sdk.BetaToolRunnerParams{
		BetaMessageNewParams: sdk.BetaMessageNewParams{
			Model:     sdk.Model(model),
			MaxTokens: maxTokens,
			System:    []sdk.BetaTextBlockParam{{Text: system}},
			Messages:  []sdk.BetaMessageParam{sdk.NewBetaUserMessage(sdk.NewBetaTextBlock(user))},
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
