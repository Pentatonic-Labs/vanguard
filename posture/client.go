package posture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultUserAgent = "vanguard-posture/0.1 (+https://github.com/Pentatonic-Labs/vanguard)"

// httpDoer is the subset of *http.Client used here, so tests can inject a
// transport that points at an httptest server.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Option configures a checker.
type Option func(*config)

// config holds the injectable, shared parts of every checker.
type config struct {
	baseURL string
	client  httpDoer
}

// WithBaseURL overrides the service base URL (for tests).
func WithBaseURL(u string) Option { return func(c *config) { c.baseURL = u } }

// WithHTTPClient injects an HTTP client (for tests). The default client has a
// 10-second timeout.
func WithHTTPClient(cl httpDoer) Option { return func(c *config) { c.client = cl } }

// applyOptions applies opts over defaults.
func applyOptions(opts []Option) *config {
	c := &config{client: &http.Client{Timeout: 10 * time.Second}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// getJSON performs a read-only GET and decodes the JSON body into v. The
// Authorization header is set from token using scheme (e.g. "Bearer "), and the
// token is redacted from every error path so secrets never leak into logs.
func getJSON(ctx context.Context, client httpDoer, url, token, scheme string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", scheme+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return redact(fmt.Errorf("get %s: %w", url, err), token)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return redact(fmt.Errorf("get %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body))), token)
	}

	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return redact(fmt.Errorf("decode %s: %w", url, err), token)
	}
	return nil
}

// redact replaces every occurrence of token in the error message. A non-empty
// token must never reach a log line or a returned error.
func redact(err error, token string) error {
	if token == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "REDACTED"))
}
