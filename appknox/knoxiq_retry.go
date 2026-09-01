package appknox

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Retry knobs. These are variables rather than constants so tests can collapse
// the backoff; production code must not reassign them.
var (
	// knoxiqMaxAttempts bounds total tries, including the first.
	knoxiqMaxAttempts = 3

	// knoxiqRetryBaseDelay is the first backoff interval; it doubles per retry.
	knoxiqRetryBaseDelay = 500 * time.Millisecond
)

// getWithRetry GETs a KnoxIQ resource, retrying only genuinely transient
// failures and decoding into out.
//
// The policy is deliberately asymmetric:
//
//   - transport errors, 429 and 5xx are transient   -> retry with backoff
//   - 4xx (401/403/404 especially) are not          -> fail on the first attempt
//
// Retrying a rejected credential cannot succeed; it only delays the run and
// buries the real cause under a generic "gave up" message.
func (s *KnoxIQService) getWithRetry(ctx context.Context, url string, out interface{}) error {
	var lastErr error

	for attempt := 1; attempt <= knoxiqMaxAttempts; attempt++ {
		req, err := s.client.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}

		if _, err = s.client.Do(ctx, req, out); err == nil {
			return nil
		}
		lastErr = err

		if !isRetryableKnoxIQError(err) {
			return explainKnoxIQError(err)
		}
		if attempt == knoxiqMaxAttempts {
			break
		}
		if err := sleepBackoff(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("giving up after %d attempts: %w", knoxiqMaxAttempts, lastErr)
}

// sleepBackoff waits out the exponential delay for the given attempt, aborting
// early if the context is cancelled.
func sleepBackoff(ctx context.Context, attempt int) error {
	delay := knoxiqRetryBaseDelay << (attempt - 1)
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// isRetryableKnoxIQError reports whether another attempt could plausibly work.
//
// A non-API error means the request never got a response (DNS, connection
// reset, timeout), which is exactly the transient case worth retrying.
func isRetryableKnoxIQError(err error) bool {
	var apiErr *ErrorResponse
	if !errors.As(err, &apiErr) {
		return true
	}
	if apiErr.Response == nil {
		return false
	}
	status := apiErr.Response.StatusCode
	return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
}

// explainKnoxIQError adds the one piece of context that is not obvious from a
// bare 401: Appknox exposes two different credentials on the same host, and the
// Public API's bearer will not authenticate against KnoxIQ.
func explainKnoxIQError(err error) error {
	var apiErr *ErrorResponse
	if errors.As(err, &apiErr) && apiErr.Response != nil {
		switch apiErr.Response.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf(
				"%w -- KnoxIQ expects the api/v2 token as 'Token <token>'; the Public "+
					"API's '<keyId>:<secret>' bearer will not authenticate here", err)
		case http.StatusNotFound:
			return fmt.Errorf("%w -- is KnoxIQ enabled on this host?", err)
		}
	}
	return err
}
