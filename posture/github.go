package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

// githubTokenEnv is the environment variable holding the GitHub API token.
const githubTokenEnv = "VANGUARD_GITHUB_TOKEN"

// GitHubChecker performs read-only posture checks against a GitHub org.
//
// Checks:
//   - two-factor enforcement: whether any org member lacks 2FA.
type GitHubChecker struct {
	org   string
	token string
	cfg   *config
}

// NewGitHubChecker returns a checker for org. The API token is read from
// githubTokenEnv; when unset, Check reports a "not configured" result.
func NewGitHubChecker(org string, opts ...Option) *GitHubChecker {
	return &GitHubChecker{org: org, token: os.Getenv(githubTokenEnv), cfg: applyOptions(opts)}
}

func (c *GitHubChecker) baseURL() string {
	if c.cfg.baseURL != "" {
		return c.cfg.baseURL
	}
	return "https://api.github.com"
}

// Check reports whether the org enforces two-factor authentication.
func (c *GitHubChecker) Check(ctx context.Context) ([]Result, error) {
	const check = "two-factor enforcement"
	if c.token == "" {
		return []Result{notConfigured("github", check, githubTokenEnv)}, nil
	}

	// GET /orgs/{org}/members?filter=2fa_disabled lists members without 2FA.
	// Requires an org-admin token with the read:org scope.
	url := c.baseURL() + "/orgs/" + c.org + "/members?filter=2fa_disabled"
	var members []json.RawMessage
	if err := getJSON(ctx, c.cfg.client, url, c.token, "Bearer ", &members); err != nil {
		return nil, err
	}

	pass := len(members) == 0
	detail := "all org members have 2FA enabled"
	if !pass {
		detail = fmt.Sprintf("%d member(s) without 2FA", len(members))
	}
	return []Result{{Service: "github", Check: check, Pass: pass, Detail: detail}}, nil
}
