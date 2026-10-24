// Package pipeline wires the reactive CVM loop end to end:
// collect inventory -> fetch/query feeds -> parse -> normalize -> match -> triage.
package pipeline

import (
	"context"
	"fmt"
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
	FetchKEV       func(ctx context.Context) ([]byte, error)
	FetchNVD       func(ctx context.Context) ([]byte, error)
	FetchOSVExport func(ctx context.Context, ecosystem string) ([]byte, error)

	ParseKEV       func(data []byte) ([]cvmcore.Vuln, error)
	ParseNVD       func(data []byte) ([]cvmcore.Vuln, error)
	ParseOSVExport func(data []byte) ([]cvmcore.Vuln, error)

	// OSVEcosystem names the OSV export to download (e.g. "Debian").
	OSVEcosystem string

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
	if out.FetchOSVExport == nil {
		out.FetchOSVExport = fc.FetchOSVExport
	}
	if out.ParseKEV == nil {
		out.ParseKEV = ingest.ParseKEV
	}
	if out.ParseNVD == nil {
		out.ParseNVD = ingest.ParseNVD
	}
	if out.ParseOSVExport == nil {
		out.ParseOSVExport = ingest.ParseOSVExport
	}
	if out.OSVEcosystem == "" {
		out.OSVEcosystem = "Debian"
	}
	if out.CollectPackages == nil {
		out.CollectPackages = inventory.CollectOSPackages
	}
	return out
}

// Run executes the reactive loop and returns triage decisions, highest score
// first. Every step runs through the configured (or default) functions, so the
// whole pipeline is testable offline.
func Run(ctx context.Context, cfg Config) ([]cvmcore.Decision, error) {
	cfg = cfg.withDefaults()

	// Collect inventory first so it is available for matching.
	pkgs, err := cfg.CollectPackages()
	if err != nil {
		return nil, fmt.Errorf("collect inventory: %w", err)
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

	raw, err = cfg.FetchOSVExport(ctx, cfg.OSVEcosystem)
	if err != nil {
		return nil, fmt.Errorf("fetch OSV export: %w", err)
	}
	osv, err := cfg.ParseOSVExport(raw)
	if err != nil {
		return nil, fmt.Errorf("parse OSV export: %w", err)
	}
	vulns = append(vulns, osv...)

	normalized := normalize.Normalize(vulns)
	return triage.Triage(match.Match(normalized, pkgs)), nil
}
