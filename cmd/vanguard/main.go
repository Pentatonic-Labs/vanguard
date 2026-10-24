// Command vanguard is the Vanguard CLI entrypoint.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/pipeline"
)

// version is overridden at build time via -ldflags.
var version = "0.1.0-dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("vanguard %s\n", version)
		return
	}

	// scan is the default command: run the reactive CVM loop against the live
	// feeds (KEV, NVD, OSV export) and report matches, highest score first.
	cfg := pipeline.Config{}
	if os.Getenv("NVD_API_KEY") == "" {
		// Without a key NVD rate-limits immediately; skip it rather than fail.
		cfg.FetchNVD = func(context.Context) ([]byte, error) { return []byte("{}"), nil }
		cfg.ParseNVD = func([]byte) ([]cvmcore.Vuln, error) { return nil, nil }
	}

	decisions, err := pipeline.Run(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vanguard:", err)
		os.Exit(1)
	}

	var matches []cvmcore.Decision
	bySource := map[string]int{}
	for _, d := range decisions {
		bySource[d.Match.Vuln.Source]++
		if len(d.Match.Packages) > 0 {
			matches = append(matches, d)
		}
	}

	fmt.Printf("vulns: %d (by source: %v)\n", len(decisions), bySource)
	fmt.Printf("matches: %d\n\n", len(matches))
	for _, m := range matches {
		fmt.Printf("%-30s %-8s %-8s -> %v\n",
			m.Match.Vuln.ID, m.Match.Vuln.Severity, m.Action, m.Match.Packages)
	}
}
