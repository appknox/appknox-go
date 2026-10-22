package helper

import (
	"fmt"
	"net"
	"net/url"
)

// validateEndpoint refuses plaintext HTTP to a non-loopback host: the access
// token and the checkout's file contents (tool results) would otherwise cross
// the network in cleartext (CWE-319). Autofix gates on it before the first turn.
func validateEndpoint(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("autofix: invalid host: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("autofix: refusing plaintext http to non-loopback host %q — use https", u.Host)
}

// isLoopback reports whether host is localhost or a loopback IP.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
