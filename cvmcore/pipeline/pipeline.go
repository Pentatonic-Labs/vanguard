// Package pipeline wires the reactive CVM loop end to end:
// collect inventory -> fetch/query feeds -> parse -> normalize -> match -> triage.
package pipeline

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/fetch"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/ingest"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/match"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/normalize"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/triage"
	"github.com/Pentatonic-Labs/vanguard/inventory"
)

// Config configures a pipeline run. Zero-valued fields fall back to production
// defaults, so tests can override only what they need.
type Config struct {
	FetchKEV func(ctx context.Context) ([]byte, error)
	FetchNVD func(ctx context.Context) ([]byte, error)
	QueryOSV func(ctx context.Context, purls []string) ([]byte, error)

	ParseKEV           func(data []byte) ([]cvmcore.Vuln, error)
	ParseNVD           func(data []byte) ([]cvmcore.Vuln, error)
	ParseOSVQueryBatch func(data []byte) ([]cvmcore.Vuln, error)

	CollectPackages func() ([]inventory.Package, error)
}

// withDefaults fills unset fields with production defaults.
func (c Config) withDefaults() Config {
	out := c
	fc := fetch.NewClient(30 * time.Second)
	if out.FetchKEV == nil {
		out.FetchKEV = fc.FetchKEV
	}
	if out.FetchNVD == nil {
		out.FetchNVD = func(ctx context.Context) ([]byte, error) {
			return fc.FetchNVDRecent(ctx, time.Now().Add(-30*24*time.Hour))
		}
	}
	if out.QueryOSV == nil {
		out.QueryOSV = fc.QueryBatch
	}
	if out.ParseKEV == nil {
		out.ParseKEV = ingest.ParseKEV
	}
	if out.ParseNVD == nil {
		out.ParseNVD = ingest.ParseNVD
	}
	if out.ParseOSVQueryBatch == nil {
		out.ParseOSVQueryBatch = ingest.ParseOSVQueryBatch
	}
	if out.CollectPackages == nil {
		out.CollectPackages = inventory.CollectOSPackages
	}
	return out
}

// osvPurl converts an inventory purl into the form the OSV query API expects:
// a distro namespace is added and the version (with any epoch) is stripped.
// OSV's keyed query returns every vuln for the package, which Match then filters
// by version range.
func osvPurl(p string) string {
	if rest, ok := strings.CutPrefix(p, "pkg:deb/"); ok {
		if i := strings.IndexByte(rest, '@'); i >= 0 {
			rest = rest[:i]
		}
		return "pkg:deb/debian/" + rest
	}
	if i := strings.IndexByte(p, '@'); i >= 0 {
		return p[:i]
	}
	return p
}

// Run executes the reactive loop and returns triage decisions, highest score
// first. Every step runs through the configured (or default) functions, so the
// whole pipeline is testable offline.
func Run(ctx context.Context, cfg Config) ([]cvmcore.Decision, error) {
	cfg = cfg.withDefaults()

	// Collect inventory first so OSV can be queried for the installed purls.
	pkgs, err := cfg.CollectPackages()
	if err != nil {
		return nil, fmt.Errorf("collect inventory: %w", err)
	}
	purls := make([]string, 0, len(pkgs))
	seenPurl := make(map[string]bool)
	for _, p := range pkgs {
		if p.Purl == "" {
			continue
		}
		q := osvPurl(p.Purl)
		if !seenPurl[q] {
			seenPurl[q] = true
			purls = append(purls, q)
		}
	}

	var vulns []cvmcore.Vuln

	raw, err := cfg.FetchKEV(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch KEV: %w", err)
	}
	kev, err := cfg.ParseKEV(raw)
	if err != nil {
		return nil, fmt.Errorf("parse KEV: %w", err)
	}
	vulns = append(vulns, kev...)

	raw, err = cfg.FetchNVD(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch NVD: %w", err)
	}
	nvd, err := cfg.ParseNVD(raw)
	if err != nil {
		return nil, fmt.Errorf("parse NVD: %w", err)
	}
	vulns = append(vulns, nvd...)

	if len(purls) > 0 {
		raw, err := cfg.QueryOSV(ctx, purls)
		if err != nil {
			return nil, fmt.Errorf("query OSV: %w", err)
		}
		osv, err := cfg.ParseOSVQueryBatch(raw)
		if err != nil {
			return nil, fmt.Errorf("parse OSV: %w", err)
		}
		vulns = append(vulns, osv...)
	}

	normalized := normalize.Normalize(vulns)
	return triage.Triage(match.Match(normalized, pkgs)), nil
}
