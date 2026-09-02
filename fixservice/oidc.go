package fixservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Credential resolution for Sherrinford.
//
// In CI there is no stored secret to leak: the runner proves who it is with a
// short-lived OIDC id-token, and Sherrinford hands back a session token scoped
// to that one run. Outside CI an explicitly supplied token is used instead, for
// local development against a gateway that accepts one.

const (
	// defaultOIDCAudience must match what Sherrinford verifies, or every
	// id-token is refused.
	defaultOIDCAudience = "api://appknox-autofix"

	oidcHTTPTimeout = 30 * time.Second
	maxTokenBytes   = 1 << 20 // an id-token is a few KB; cap the read anyway
)

// actionsIDToken asks the CI runtime for an OIDC id-token for the audience.
//
// Both variables are injected by GitHub Actions when a job declares
// `permissions: id-token: write`. Their absence simply means "not in CI".
func actionsIDToken(ctx context.Context, audience string) (string, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL == "" || requestToken == "" {
		return "", nil
	}

	parsed, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("fixservice: bad ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	query := parsed.Query()
	query.Set("audience", audience)
	parsed.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)

	var payload struct {
		Value string `json:"value"`
	}
	if err := sendJSON(req, &payload); err != nil {
		return "", fmt.Errorf("fixservice: requesting the CI id-token: %w", err)
	}
	if payload.Value == "" {
		return "", errors.New("fixservice: the CI id-token response was empty")
	}
	return payload.Value, nil
}

// ExchangeForSession trades a verified CI id-token for a short-lived session
// token at Sherrinford's /v1/token.
//
// The endpoint is validated before the id-token is sent: that token is a bearer
// credential, and putting it on the wire in plaintext would hand it to anyone on
// the path.
func ExchangeForSession(ctx context.Context, gatewayURL, idToken, appknoxToken string) (string, error) {
	if err := ValidateEndpoint(gatewayURL); err != nil {
		return "", err
	}
	// Both credentials go up: the id-token proves which run is calling, the
	// Appknox token proves the account is entitled to spend. Sherrinford's
	// repository allow-list is open by default, so this is what authorises.
	body, err := json.Marshal(map[string]string{
		"oidc_token": idToken, "appknox_token": appknoxToken})
	if err != nil {
		return "", err
	}
	endpoint := Config{URL: gatewayURL}.base() + "/v1/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	var payload struct {
		SessionToken string `json:"session_token"`
	}
	if err := sendJSON(req, &payload); err != nil {
		return "", fmt.Errorf("fixservice: exchanging the id-token for a session: %w", err)
	}
	if payload.SessionToken == "" {
		return "", errors.New("fixservice: the token exchange returned no session token")
	}
	return payload.SessionToken, nil
}

// ResolveToken returns the credential to present to Sherrinford.
//
// OIDC wins whenever the runner can produce an id-token, even if a static token
// was also supplied: a per-run credential is strictly better than a stored one.
//
// A refused exchange is an ERROR, never a fallback to the static token. Falling
// back would turn "this repository is not allow-listed" into a silent downgrade,
// which is precisely the signal an operator needs to see.
func ResolveToken(ctx context.Context, gatewayURL, staticToken, appknoxToken string) (string, error) {
	audience := os.Getenv("APPKNOX_AUTOFIX_OIDC_AUDIENCE")
	if audience == "" {
		audience = defaultOIDCAudience
	}

	idToken, err := actionsIDToken(ctx, audience)
	if err != nil {
		return "", err
	}
	if idToken != "" {
		return ExchangeForSession(ctx, gatewayURL, idToken, appknoxToken)
	}
	if staticToken != "" {
		return staticToken, nil
	}
	return "", errors.New(
		"no credential for the gateway: run in CI with 'permissions: id-token: write', " +
			"or pass --fix-token / APPKNOX_AUTOFIX_FIX_TOKEN")
}

// sendJSON performs the request and decodes a JSON body, surfacing the status on
// failure. Response bodies are never logged: they carry credentials.
func sendJSON(req *http.Request, out interface{}) error {
	client := &http.Client{Timeout: oidcHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s returned %d", req.URL.Path, resp.StatusCode)
	}
	return json.Unmarshal(data, out)
}
