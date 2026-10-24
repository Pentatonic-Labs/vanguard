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

	// OSVEcosystem names the OSV export to download. When empty it is
	// detected from the host OS (see DetectOSID).
	OSVEcosystem string

	// DetectOSID returns the host OS ID (e.g. "ubuntu", "debian"); defaults
	// to inventory.DetectOSID.
	DetectOSID func() string

	// DetectOSVersion returns the installed OS release (e.g. "24.04"); defaults
	// to inventory.DetectOSVersion.
	DetectOSVersion func() string

	// OnFeedError, if set, is called when a feed fails; Run then skips that
	// feed and continues. When nil, the first feed failure aborts Run.
	OnFeedError func(feed string, err error)

	CollectPackages func() ([]inventory.Package, error)
}

// withDefaults fills unset fields with production defaults.
func (c Config) withDefaults() Config {
	out := c
	fc := fetch.NewClient(5 * time.Minute) // the Ubuntu OSV export is ~791 MiB
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
	if out.DetectOSVersion == nil {
		out.DetectOSVersion = inventory.DetectOSVersion
	}
	if out.DetectOSID == nil {
		out.DetectOSID = inventory.DetectOSID
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

	// runFeed fetches and parses one feed, appending its vulns. When
	// OnFeedError is set a failure is reported and skipped; otherwise it
	// aborts the run.
	runFeed := func(name string, fetchFn func(context.Context) ([]byte, error), parseFn func([]byte) ([]cvmcore.Vuln, error)) error {
		raw, err := fetchFn(ctx)
		if err == nil {
			var parsed []cvmcore.Vuln
			if parsed, err = parseFn(raw); err == nil {
				vulns = append(vulns, parsed...)
				return nil
			}
		}
		if cfg.OnFeedError != nil {
			cfg.OnFeedError(name, err)
			return nil
		}
		return fmt.Errorf("%s: %w", name, err)
	}

	if err := runFeed("KEV", cfg.FetchKEV, cfg.ParseKEV); err != nil {
		return nil, err
	}
	if err := runFeed("NVD", cfg.FetchNVD, cfg.ParseNVD); err != nil {
		return nil, err
	}
	osvEco := cfg.OSVEcosystem
	if osvEco == "" {
		osvEco = inventory.OSVEcosystem(cfg.DetectOSID())
	}
	fetchOSV := func(ctx context.Context) ([]byte, error) { return cfg.FetchOSVExport(ctx, osvEco) }
	if err := runFeed("OSV", fetchOSV, cfg.ParseOSVExport); err != nil {
		return nil, err
	}

	normalized := normalize.Normalize(vulns)
	return triage.Triage(match.Match(normalized, pkgs, cfg.DetectOSVersion())), nil
}
