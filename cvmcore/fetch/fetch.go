// Package fetch retrieves vulnerability feed documents over HTTP.
package fetch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default feed endpoint URLs.
const (
	DefaultKEVURL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultOSVQueryURL = "https://api.osv.dev/v1/querybatch"
	DefaultNVDURL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

const defaultUserAgent = "vanguard/0.1 (+https://github.com/Pentatonic-Labs/vanguard)"

// maxResponseBytes caps a feed response body. It is generous — the Ubuntu OSV
// export is ~791 MiB — but prevents unbounded memory use from a misbehaving or
// malicious server.
const maxResponseBytes = 1 << 30 // 1 GiB

// Client fetches vulnerability feed documents over HTTP with a mandatory
// timeout, a User-Agent, and simple rate-limit courtesy between requests.
type Client struct {
	// URLs may be overridden (e.g. to point at a test server).
	KEVURL      string
	OSVQueryURL string
	NVDURL      string

	// NVDPageSize is the NVD resultsPerPage used when paginating. Zero falls
	// back to 2000.
	NVDPageSize int

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
		KEVURL:      DefaultKEVURL,
		OSVQueryURL: DefaultOSVQueryURL,
		NVDURL:      DefaultNVDURL,
		NVDPageSize: 2000,
		MinDelay:    100 * time.Millisecond,
		httpClient:  &http.Client{Timeout: timeout},
		userAgent:   defaultUserAgent,
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

// FetchNVD downloads the NVD 2.0 CVE feed.
func (c *Client) FetchNVD(ctx context.Context) ([]byte, error) {
	return c.get(ctx, c.NVDURL)
}

// OSVExportBaseURL is the base URL for OSV.dev ecosystem vulnerability exports.
const OSVExportBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// FetchOSVExport downloads the full OSV vulnerability export for an ecosystem
// (e.g. "Debian") as a ZIP of per-vulnerability JSON files. The querybatch API
// returns only id/modified stubs, so the export is how full records with
// affected version ranges are obtained.
func (c *Client) FetchOSVExport(ctx context.Context, ecosystem string) ([]byte, error) {
	return c.get(ctx, OSVExportBaseURL+"/"+ecosystem+"/all.zip")
}

// maxQueryBatch is the largest number of purls sent per OSV querybatch request.
const maxQueryBatch = 1000

// QueryBatch queries OSV.dev for vulnerabilities affecting the given package
// purls, chunking into requests of at most maxQueryBatch purls. It returns a
// document of the form {"results":[...]}, the same shape OSV.dev returns.
func (c *Client) QueryBatch(ctx context.Context, purls []string) ([]byte, error) {
	all := make([]json.RawMessage, 0)
	for start := 0; start < len(purls); start += maxQueryBatch {
		end := start + maxQueryBatch
		if end > len(purls) {
			end = len(purls)
		}
		queries := make([]map[string]map[string]string, 0, end-start)
		for _, p := range purls[start:end] {
			queries = append(queries, map[string]map[string]string{"package": {"purl": p}})
		}
		body, err := json.Marshal(map[string]any{"queries": queries})
		if err != nil {
			return nil, fmt.Errorf("marshal OSV querybatch: %w", err)
		}
		respBody, err := c.postJSON(ctx, c.OSVQueryURL, body)
		if err != nil {
			return nil, err
		}
		var page struct {
			Results []json.RawMessage `json:"results"`
		}
		if err := json.Unmarshal(respBody, &page); err != nil {
			return nil, fmt.Errorf("parse OSV querybatch response: %w", err)
		}
		all = append(all, page.Results...)
	}
	out, err := json.Marshal(struct {
		Results []json.RawMessage `json:"results"`
	}{Results: all})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FetchNVDRecent downloads CVEs modified on or after since, paginating through
// all results. NVD 2.0 returns at most 2000 CVEs per page; without a recency
// filter and pagination only the first (oldest) page is fetched.
func (c *Client) FetchNVDRecent(ctx context.Context, since time.Time) ([]byte, error) {
	pageSize := c.NVDPageSize
	if pageSize <= 0 {
		pageSize = 2000
	}
	apiKey := strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	var all []json.RawMessage
	for start := 0; ; start += pageSize {
		q := url.Values{}
		q.Set("lastModStartDate", since.UTC().Format("2006-01-02T15:04:05.000-07:00"))
		q.Set("lastModEndDate", time.Now().UTC().Format("2006-01-02T15:04:05.000-07:00"))
		q.Set("resultsPerPage", strconv.Itoa(pageSize))
		q.Set("startIndex", strconv.Itoa(start))
		if apiKey != "" {
			q.Set("apiKey", apiKey)
		}
		body, err := c.retryGET(ctx, c.NVDURL+"?"+q.Encode())
		if err != nil {
			return nil, err
		}
		var page struct {
			Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("parse NVD page: %w", err)
		}
		all = append(all, page.Vulnerabilities...)
		if len(page.Vulnerabilities) < pageSize {
			break
		}
	}
	out, err := json.Marshal(struct {
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}{Vulnerabilities: all})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// retryGET performs a GET, retrying on HTTP 429 (rate limiting) with
// exponential backoff, honoring ctx.
func (c *Client) retryGET(ctx context.Context, url string) ([]byte, error) {
	const maxRetries = 3
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		body, err := c.get(ctx, url)
		if err == nil {
			return body, nil
		}
		if !strings.Contains(err.Error(), "429") {
			return nil, err
		}
		lastErr = err
		if attempt < maxRetries {
			delay := time.Duration(1<<attempt) * 2 * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	return nil, lastErr
}

// postJSON performs a POST with a JSON body and returns the response body.
func (c *Client) postJSON(ctx context.Context, url string, body []byte) ([]byte, error) {
	if err := c.throttle(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("post %s: unexpected status %d", url, resp.StatusCode)
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if len(out) > maxResponseBytes {
		return nil, fmt.Errorf("read %s: response exceeds %d bytes", url, maxResponseBytes)
	}
	return out, nil
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("read %s: response exceeds %d bytes", url, maxResponseBytes)
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
