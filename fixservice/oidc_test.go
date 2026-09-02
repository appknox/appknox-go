package fixservice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// actionsTokenServer stands in for the Actions OIDC endpoint that hands a
// workflow its id-token.
func actionsTokenServer(t *testing.T, idToken string) (*httptest.Server, *string) {
	t.Helper()
	gotAudience := new(string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer request-tok", r.Header.Get("Authorization"))
		*gotAudience = r.URL.Query().Get("audience")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": idToken})
	}))
	t.Cleanup(srv.Close)
	return srv, gotAudience
}

// sherrinfordServer stands in for POST /v1/token.
func sherrinfordServer(t *testing.T, status int, sessionToken string) (*httptest.Server, *string) {
	t.Helper()
	gotOIDC := new(string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/token", r.URL.Path)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		*gotOIDC = body["oidc_token"]
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session_token": sessionToken, "run_id": "99",
				"expires_at": 1.0, "scopes": []string{"model:invoke"},
			})
		}
	}))
	t.Cleanup(srv.Close)
	return srv, gotOIDC
}

func withActionsEnv(t *testing.T, url string) {
	t.Helper()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", url)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-tok")
}

// In CI the credential is minted per run: no long-lived secret is stored.
func TestResolveToken_exchangesOIDCForASession(t *testing.T) {
	actions, gotAudience := actionsTokenServer(t, "the.id.token")
	withActionsEnv(t, actions.URL)
	sherrinford, gotOIDC := sherrinfordServer(t, http.StatusOK, "session-abc")

	token, err := ResolveToken(context.Background(), sherrinford.URL, "", "appknox-tok")
	require.NoError(t, err)
	require.Equal(t, "session-abc", token)
	require.Equal(t, "the.id.token", *gotOIDC, "the id-token must be forwarded verbatim")
	require.Equal(t, defaultOIDCAudience, *gotAudience)
}

// Outside CI there is no id-token, so an explicitly supplied token is used.
func TestResolveToken_fallsBackToTheExplicitToken(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	token, err := ResolveToken(context.Background(), "https://sherrinford.example", "static-tok", "")
	require.NoError(t, err)
	require.Equal(t, "static-tok", token)
}

func TestResolveToken_requiresSomething(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	_, err := ResolveToken(context.Background(), "https://sherrinford.example", "", "")
	require.Error(t, err)
}

// OIDC is preferred when available: a short-lived per-run credential beats a
// static one even when both are present.
func TestResolveToken_prefersOIDCOverAStaticToken(t *testing.T) {
	actions, _ := actionsTokenServer(t, "the.id.token")
	withActionsEnv(t, actions.URL)
	sherrinford, _ := sherrinfordServer(t, http.StatusOK, "session-abc")

	token, err := ResolveToken(context.Background(), sherrinford.URL, "static-tok", "appknox-tok")
	require.NoError(t, err)
	require.Equal(t, "session-abc", token)
}

// A refused exchange must not silently fall back to the static token: that would
// turn an allow-list rejection into a quiet downgrade.
func TestResolveToken_refusedExchangeIsAnError(t *testing.T) {
	actions, _ := actionsTokenServer(t, "the.id.token")
	withActionsEnv(t, actions.URL)
	sherrinford, _ := sherrinfordServer(t, http.StatusUnauthorized, "")

	_, err := ResolveToken(context.Background(), sherrinford.URL, "static-tok", "appknox-tok")
	require.Error(t, err)
	require.Contains(t, err.Error(), "401")
}

// The audience must match what Sherrinford verifies, or every token is refused.
func TestResolveToken_audienceIsOverridable(t *testing.T) {
	actions, gotAudience := actionsTokenServer(t, "tok")
	withActionsEnv(t, actions.URL)
	t.Setenv("APPKNOX_AUTOFIX_OIDC_AUDIENCE", "api://custom")
	sherrinford, _ := sherrinfordServer(t, http.StatusOK, "s")

	_, err := ResolveToken(context.Background(), sherrinford.URL, "", "appknox-tok")
	require.NoError(t, err)
	require.Equal(t, "api://custom", *gotAudience)
}

// The id-token is a bearer credential; it must never reach a plaintext endpoint.
func TestExchangeForSession_refusesPlaintextRemote(t *testing.T) {
	_, err := ExchangeForSession(context.Background(), "http://sherrinford.example", "tok", "ak")
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "https"), "want a plaintext refusal, got: %v", err)
}
