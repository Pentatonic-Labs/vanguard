// Package posture performs read-only posture checks against SaaS services
// (GitHub, Microsoft Entra, Cloudflare, Linear). It never mutates remote
// state: every request is an HTTP GET, and credentials come only from
// environment variables. There is deliberately no offensive probing here.
package posture

import "context"

// Checker runs read-only posture checks against a SaaS service.
type Checker interface {
	// Check runs the checks and returns their results. Implementations must
	// be read-only and must never mutate remote state.
	Check(ctx context.Context) ([]Result, error)
}

// Result is the outcome of a single posture check.
type Result struct {
	Service string // "github", "entra", "cloudflare", "linear"
	Check   string // short, human-readable check name
	Pass    bool   // whether the posture property holds
	Detail  string // explanation, evidence, or remediation hint
}

// notConfigured is the result emitted when a checker's credential env var is
// unset. It is a result, not an error: "no credentials" is a reportable
// posture state rather than a failure of the checker.
func notConfigured(service, check, envVar string) Result {
	return Result{
		Service: service,
		Check:   check,
		Pass:    false,
		Detail:  envVar + " is not set; check not run",
	}
}
