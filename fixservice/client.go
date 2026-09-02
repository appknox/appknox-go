// Package fixservice configures and guards the connection to Sherrinford, the
// service that holds the provider LLM key.
//
// It no longer submits files anywhere. The fix is produced on this machine
// against the local checkout; only model turns cross the wire, and they go to
// Sherrinford's Anthropic-compatible endpoint. Sherrinford has no route that
// accepts source, so there is nothing here to upload it with.
package fixservice

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Config points the client at Sherrinford with its scoped token.
type Config struct {
	URL   string // Sherrinford base URL
	Token string // short-lived session token (sent as the model API key)
}

func (c Config) base() string { return strings.TrimRight(c.URL, "/") }

// ValidateEndpoint refuses plaintext HTTP to a non-loopback host: the scoped
// token and the located file/prompt would otherwise cross the network in
// cleartext. Exported so the whole flow (locate + fix) can gate on it up front.
func ValidateEndpoint(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("fixservice: invalid fix-url: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("fixservice: refusing plaintext http to non-loopback host %q — use https", u.Host)
}

// isLoopback reports whether host is localhost or a loopback IP.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
