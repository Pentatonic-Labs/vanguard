// Package fetch retrieves vulnerability feed documents over HTTP.
package fetch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Default feed endpoint URLs.
const (
	DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultOSVURL = "https://api.osv.dev/v1/vulns"
	DefaultNVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

const defaultUserAgent = "vanguard/0.1 (+https://github.com/Pentatonic-Labs/vanguard)"

// Client fetches vulnerability feed documents over HTTP with a mandatory
// timeout, a User-Agent, and simple rate-limit courtesy between requests.
type Client struct {
	// URLs may be overridden (e.g. to point at a test server).
	KEVURL string
	OSVURL string
	NVDURL string

	// MinDelay is the minimum gap between requests. Zero disables the delay.
	MinDelay time.Duration

	httpClient *http.Client
	userAgent  string

	mu      sync.Mutex
	lastReq time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithMinDelay sets the minimum delay between requests.
func WithMinDelay(d time.Duration) Option {
	return func(c *Client) { c.MinDelay = d }
}

// NewClient returns a Client with the given timeout, a default User-Agent, and
// a small default minimum delay between requests.
func NewClient(timeout time.Duration, opts ...Option) *Client {
	c := &Client{
		KEVURL:     DefaultKEVURL,
		OSVURL:     DefaultOSVURL,
		NVDURL:     DefaultNVDURL,
		MinDelay:   100 * time.Millisecond,
		httpClient: &http.Client{Timeout: timeout},
		userAgent:  defaultUserAgent,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// FetchKEV downloads the CISA Known Exploited Vulnerabilities catalog.
func (c *Client) FetchKEV(ctx context.Context) ([]byte, error) {
	return c.get(ctx, c.KEVURL)
}

// FetchOSV downloads the OSV.dev vulnerability list.
func (c *Client) FetchOSV(ctx context.Context) ([]byte, error) {
	return c.get(ctx, c.OSVURL)
}

// FetchNVD downloads the NVD 2.0 CVE feed.
func (c *Client) FetchNVD(ctx context.Context) ([]byte, error) {
	return c.get(ctx, c.NVDURL)
}

// get performs a GET with rate-limit courtesy and returns the response body.
func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	if err := c.throttle(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: unexpected status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	return body, nil
}

// throttle enforces the minimum gap between requests, honoring ctx.
func (c *Client) throttle(ctx context.Context) error {
	if c.MinDelay <= 0 {
		return nil
	}

	c.mu.Lock()
	wait := c.MinDelay - time.Since(c.lastReq)
	if wait > 0 {
		c.lastReq = time.Now().Add(wait)
	} else {
		c.lastReq = time.Now()
	}
	c.mu.Unlock()

	if wait <= 0 {
		return nil
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
