package posture

import (
	"context"
	"fmt"
	"os"
)

// cloudflareTokenEnv is the environment variable holding the Cloudflare API token.
const cloudflareTokenEnv = "VANGUARD_CLOUDFLARE_TOKEN"

// CloudflareChecker performs read-only posture checks against a Cloudflare zone.
//
// Checks:
//   - DNSSEC enabled: the zone's DNSSEC status is "active".
//   - TLS mode: the zone's SSL mode is not "off".
type CloudflareChecker struct {
	zone  string
	token string
	cfg   *config
}

// NewCloudflareChecker returns a checker for zone (a zone ID). The token is
// read from cloudflareTokenEnv.
func NewCloudflareChecker(zone string, opts ...Option) *CloudflareChecker {
	return &CloudflareChecker{zone: zone, token: os.Getenv(cloudflareTokenEnv), cfg: applyOptions(opts)}
}

func (c *CloudflareChecker) baseURL() string {
	if c.cfg.baseURL != "" {
		return c.cfg.baseURL
	}
	return "https://api.cloudflare.com/client/v4"
}

// Check reports DNSSEC and TLS posture for the zone.
func (c *CloudflareChecker) Check(ctx context.Context) ([]Result, error) {
	if c.token == "" {
		return []Result{notConfigured("cloudflare", "DNSSEC + TLS", cloudflareTokenEnv)}, nil
	}

	var results []Result

	dnssecURL := c.baseURL() + "/zones/" + c.zone + "/dnssec"
	var dnssec struct {
		Result struct {
			Status string `json:"status"`
		} `json:"result"`
	}
	if err := getJSON(ctx, c.cfg.client, dnssecURL, c.token, "Bearer ", &dnssec); err != nil {
		return nil, err
	}
	results = append(results, Result{
		Service: "cloudflare",
		Check:   "DNSSEC enabled",
		Pass:    dnssec.Result.Status == "active",
		Detail:  fmt.Sprintf("dnssec status: %q", dnssec.Result.Status),
	})

	tlsURL := c.baseURL() + "/zones/" + c.zone + "/settings/ssl"
	var tls struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	if err := getJSON(ctx, c.cfg.client, tlsURL, c.token, "Bearer ", &tls); err != nil {
		return nil, err
	}
	results = append(results, Result{
		Service: "cloudflare",
		Check:   "TLS mode",
		Pass:    tls.Result.Value != "off",
		Detail:  fmt.Sprintf("ssl mode: %q", tls.Result.Value),
	})

	return results, nil
}
