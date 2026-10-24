// Package pipeline wires the reactive CVM loop end to end:
// fetch -> parse -> normalize -> match -> triage.
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
	FetchKEV func(ctx context.Context) ([]byte, error)
	FetchOSV func(ctx context.Context) ([]byte, error)
	FetchNVD func(ctx context.Context) ([]byte, error)

	ParseKEV func(data []byte) ([]cvmcore.Vuln, error)
	ParseOSV func(data []byte) ([]cvmcore.Vuln, error)
	ParseNVD func(data []byte) ([]cvmcore.Vuln, error)

	CollectPackages func() ([]inventory.Package, error)
}

// withDefaults fills unset fields with production defaults.
func (c Config) withDefaults() Config {
	out := c
	fc := fetch.NewClient(30 * time.Second)
	if out.FetchKEV == nil {
		out.FetchKEV = fc.FetchKEV
	}
	if out.FetchOSV == nil {
		out.FetchOSV = fc.FetchOSV
	}
	if out.FetchNVD == nil {
		out.FetchNVD = fc.FetchNVD
	}
	if out.ParseKEV == nil {
		out.ParseKEV = ingest.ParseKEV
	}
	if out.ParseOSV == nil {
		out.ParseOSV = ingest.ParseOSV
	}
	if out.ParseNVD == nil {
		out.ParseNVD = ingest.ParseNVD
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

	steps := []struct {
		name  string
		fetch func(context.Context) ([]byte, error)
		parse func([]byte) ([]cvmcore.Vuln, error)
	}{
		{"KEV", cfg.FetchKEV, cfg.ParseKEV},
		{"OSV", cfg.FetchOSV, cfg.ParseOSV},
		{"NVD", cfg.FetchNVD, cfg.ParseNVD},
	}

	var vulns []cvmcore.Vuln
	for _, s := range steps {
		raw, err := s.fetch(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", s.name, err)
		}
		parsed, err := s.parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", s.name, err)
		}
		vulns = append(vulns, parsed...)
	}

	normalized := normalize.Normalize(vulns)

	pkgs, err := cfg.CollectPackages()
	if err != nil {
		return nil, fmt.Errorf("collect inventory: %w", err)
	}
	return triage.Triage(match.Match(normalized, pkgs)), nil
}
