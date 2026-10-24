package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// WithCacheDir enables on-disk caching of large downloads. When set, requests
// are made conditionally (If-None-Match) and a 304 Not Modified response
// returns the previously cached body.
func WithCacheDir(dir string) Option {
	return func(c *Client) { c.cacheDir = dir }
}

// DefaultCacheDir returns the default on-disk cache location.
func DefaultCacheDir() string {
	d, err := os.UserCacheDir()
	if err != nil || d == "" {
		d = os.TempDir()
	}
	return filepath.Join(d, "vanguard")
}

// getCached performs a GET with on-disk caching and a conditional request. On a
// 304 Not Modified it returns the cached body; on a 200 it stores the body and
// ETag for the next run.
func (c *Client) getCached(ctx context.Context, url string) ([]byte, error) {
	if c.cacheDir == "" {
		return c.get(ctx, url)
	}
	if err := c.throttle(ctx); err != nil {
		return nil, err
	}

	key := cacheKey(url)
	bodyPath := filepath.Join(c.cacheDir, key+".body")
	etagPath := filepath.Join(c.cacheDir, key+".etag")
	etag, _ := os.ReadFile(etagPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	if len(etag) > 0 {
		req.Header.Set("If-None-Match", string(etag))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		body, err := os.ReadFile(bodyPath)
		if err != nil {
			return nil, fmt.Errorf("cache miss on 304 for %s: %w", url, err)
		}
		return body, nil
	}
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

	if err := os.MkdirAll(c.cacheDir, 0o755); err == nil {
		_ = os.WriteFile(bodyPath, body, 0o644)
		if et := resp.Header.Get("ETag"); et != "" {
			_ = os.WriteFile(etagPath, []byte(et), 0o644)
		}
	}
	return body, nil
}

func cacheKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:8])
}
