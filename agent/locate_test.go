package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/stretchr/testify/require"
)

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
