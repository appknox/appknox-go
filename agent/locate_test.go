package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/stretchr/testify/require"
)

func TestLocateUserPrompt_IncludesHintAndAbstainToken(t *testing.T) {
	p := locateUserPrompt(Request{ClassHint: "com/appknox/mfva/MainActivity", Finding: "weak PRNG"})
	require.Contains(t, p, "com/appknox/mfva/MainActivity")
	require.Contains(t, p, "weak PRNG")
	require.Contains(t, p, "NONE")
}

func TestLocateWith_ReturnsValidatedPath(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app/src/main/java/com/appknox/mfva")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "MainActivity.java"), []byte("x"), 0o644))
	rel := "app/src/main/java/com/appknox/mfva/MainActivity.java"

	run := func(context.Context, Config, Request) (string, error) { return "It is " + rel, nil }
	got, err := locateWith(context.Background(), Config{}, Request{RepoRoot: root}, run)
	require.NoError(t, err)
	require.Equal(t, rel, got)
}

func TestLocateWith_AbstainsWhenModelSaysNone(t *testing.T) {
	run := func(context.Context, Config, Request) (string, error) { return "NONE", nil }
	got, err := locateWith(context.Background(), Config{}, Request{RepoRoot: t.TempDir()}, run)
	require.NoError(t, err)
	require.Equal(t, "", got)
}

func TestLocateWith_PropagatesRunnerError(t *testing.T) {
	run := func(context.Context, Config, Request) (string, error) { return "", errors.New("boom") }
	_, err := locateWith(context.Background(), Config{}, Request{RepoRoot: t.TempDir()}, run)
	require.Error(t, err)
}

func TestLocateParams_AppliesDefaults(t *testing.T) {
	p := locateParams(Config{}, Request{ClassHint: "X", Finding: "y"})
	require.Equal(t, sdk.ModelClaudeSonnet5, p.Model)
	require.Equal(t, int64(defaultMaxTokens), p.MaxTokens)
	require.Equal(t, defaultMaxIterations, p.MaxIterations)
	require.NotEmpty(t, p.System)
	require.True(t, strings.Contains(p.System[0].Text, "read-only"))
}

func TestLocateParams_HonoursOverrides(t *testing.T) {
	p := locateParams(Config{Model: "claude-x", MaxTokens: 42, MaxIterations: 3}, Request{})
	require.Equal(t, sdk.Model("claude-x"), p.Model)
	require.Equal(t, int64(42), p.MaxTokens)
	require.Equal(t, 3, p.MaxIterations)
}

func TestSdkLocate_RequiresConfig(t *testing.T) {
	// Missing Host/Token must fail before any network call.
	_, err := sdkLocate(context.Background(), Config{}, Request{RepoRoot: t.TempDir()})
	require.Error(t, err)
}

func TestAutofixBaseURL_UsesKnoxIQAutofix(t *testing.T) {
	require.Equal(t, "https://api.example.com/api/knoxiq/autofix/",
		autofixBaseURL("https://api.example.com/"))
	require.Equal(t, "https://api.example.com/api/knoxiq/autofix/",
		autofixBaseURL("https://api.example.com"))
}

func TestRewriteAutofixMessages_StripsSDKMessagesPath(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost,
		"https://api.example.com/api/knoxiq/autofix/v1/messages?beta=true", nil)
	require.NoError(t, err)
	_, err = rewriteAutofixMessages(req, func(r *http.Request) (*http.Response, error) {
		require.Equal(t, "/api/knoxiq/autofix/", r.URL.Path)
		require.Equal(t, "beta=true", r.URL.RawQuery)
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	require.NoError(t, err)
}

func TestNewAutofixSDK_PostsToKnoxIQAutofix(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"type":"error","error":{"type":"authentication_error","message":"x"}}`)
	}))
	t.Cleanup(srv.Close)

	client := sdk.NewClient(
		option.WithBaseURL(autofixBaseURL(srv.URL)),
		option.WithAPIKey("pat"),
		option.WithMiddleware(rewriteAutofixMessages),
		option.WithMaxRetries(0),
	)
	_, _ = client.Beta.Messages.New(context.Background(), sdk.BetaMessageNewParams{
		Model:     sdk.ModelClaudeSonnet5,
		MaxTokens: 16,
		Messages:  []sdk.BetaMessageParam{sdk.NewBetaUserMessage(sdk.NewBetaTextBlock("hi"))},
	})
	require.Equal(t, "/api/knoxiq/autofix/", gotPath)
}
