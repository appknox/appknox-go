// Package agent runs native, read-only LLM agents inside the CLI.
//
// The model plans and calls local read-only tools (read_file, grep, glob) over
// the checked-out repository. Each agent (locate, fix) operates independently,
// planing the next file and edits based on vulnerability context.
// Only the model turns leave the machine, routed through Mycroft
// ({APPKNOX_API_HOST}/api/knoxiq/autofix/ + a PAT, never a provider key).
// Mycroft forwards to Sherrinford, which injects the server-held provider key.
package agent

import (
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
	// defaultFixMaxTokens sizes a FIX turn, which is a different job entirely.
	//
	// A fix turn emits the edit tool call, and old_string plus new_string carry
	// real code. 1024 was enough for a one-line algorithm swap and silently too
	// small for anything larger: the reply was truncated mid-tool-use, so no edit
	// ever completed and the final message carried no text. That surfaced as "the
	// fixer produced no edit" with no reason -- indistinguishable from a
	// deliberate abstention -- and as flakiness, since whether a fix fitted the
	// budget depended on how much code it happened to touch.
	//
	// On mfva file 348 the two findings fell either side of that line: the
	// one-line Cipher swap in ExportedActivity fitted, and the hardcoded-key fix
	// in MainActivity, which has to write a key-derivation helper, did not.
	//
	// The KnoxIQ-targeting port dropped this constant and put both turns back on
	// 1024, which is how aibom-android reached 0-of-11 with seven findings
	// attempted and not one patch produced.
	defaultFixMaxTokens  = 16384
	defaultMaxIterations = 15
)

// Config uses the same Mycroft API host as every other CLI command.
type Config struct {
	Host          string // APPKNOX_API_HOST; messages go to {Host}/api/knoxiq/autofix/
	Token         string // Appknox PAT presented to Mycroft (not a provider key)
	Model         string // optional; defaults to Claude Sonnet
	MaxTokens     int64  // optional; each turn has its own default (locate: defaultTargetsMaxTokens, fix: defaultFixMaxTokens)
	MaxIterations int    // optional; defaults to defaultMaxIterations
}

// runnerParamsWithBudget builds Tool Runner params with cfg's model/token/iteration
// defaults and the given system + user prompts, with an explicit output-token budget.
// This allows different turns (locate vs fix) to have different budgets. An
// explicit cfg.MaxTokens still wins.
func runnerParamsWithBudget(cfg Config, system, user string, fallbackMaxTokens int64) sdk.BetaToolRunnerParams {
	model := cfg.Model
	if model == "" {
		model = string(sdk.ModelClaudeSonnet5)
	}
	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = fallbackMaxTokens
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
