package posture

import (
	"context"
	"os"
)

// linearTokenEnv is the environment variable holding the Linear API key.
const linearTokenEnv = "VANGUARD_LINEAR_TOKEN"

// LinearChecker reports the Linear workspace SSO posture.
//
// Linear's public API is GraphQL over HTTP POST only; there is no GET endpoint.
// Under Vanguard's GET-only posture constraint this check cannot be performed
// over the wire, so it reports that limitation rather than issuing a non-GET
// request. Review SSO in Linear's workspace settings instead.
type LinearChecker struct {
	token string
	cfg   *config
}

// NewLinearChecker returns a checker. The API key is read from linearTokenEnv.
func NewLinearChecker(opts ...Option) *LinearChecker {
	return &LinearChecker{token: os.Getenv(linearTokenEnv), cfg: applyOptions(opts)}
}

// Check reports the SSO posture as not-checkable over GET-only transport.
func (c *LinearChecker) Check(ctx context.Context) ([]Result, error) {
	const check = "SSO enabled"
	if c.token == "" {
		return []Result{notConfigured("linear", check, linearTokenEnv)}, nil
	}
	return []Result{{
		Service: "linear",
		Check:   check,
		Pass:    false,
		Detail:  "not checkable via HTTP GET: Linear's API is GraphQL over POST only; review SSO in Linear workspace settings",
	}}, nil
}
