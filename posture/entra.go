package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

// entraTokenEnv is the environment variable holding the Microsoft Graph token.
const entraTokenEnv = "VANGUARD_ENTRA_TOKEN"

// EntraChecker performs read-only posture checks against Microsoft Entra via
// the Microsoft Graph API.
//
// Checks:
//   - conditional-access policy present: at least one conditional-access
//     policy exists (a coarse signal that MFA/CA controls are configured).
type EntraChecker struct {
	tenant string
	token  string
	cfg    *config
}

// NewEntraChecker returns a checker for tenant (a tenant ID or verified domain).
// The token is read from entraTokenEnv.
func NewEntraChecker(tenant string, opts ...Option) *EntraChecker {
	return &EntraChecker{tenant: tenant, token: os.Getenv(entraTokenEnv), cfg: applyOptions(opts)}
}

func (c *EntraChecker) baseURL() string {
	if c.cfg.baseURL != "" {
		return c.cfg.baseURL
	}
	return "https://graph.microsoft.com"
}

// Check reports whether a conditional-access policy is present.
func (c *EntraChecker) Check(ctx context.Context) ([]Result, error) {
	const check = "conditional-access policy present"
	if c.token == "" {
		return []Result{notConfigured("entra", check, entraTokenEnv)}, nil
	}

	url := c.baseURL() + "/v1.0/identity/conditionalAccess/policies"
	var resp struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := getJSON(ctx, c.cfg.client, url, c.token, "Bearer ", &resp); err != nil {
		return nil, err
	}

	pass := len(resp.Value) > 0
	detail := fmt.Sprintf("%d conditional-access policies present", len(resp.Value))
	if !pass {
		detail = "no conditional-access policies present"
	}
	return []Result{{Service: "entra", Check: check, Pass: pass, Detail: detail}}, nil
}
