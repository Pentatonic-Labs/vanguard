// Command vanguard is the Vanguard CLI entrypoint.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/fetch"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/pipeline"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/remediate"
	"github.com/Pentatonic-Labs/vanguard/inventory"
)

// version is overridden at build time via -ldflags.
var version = "0.1.0-dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("vanguard %s\n", version)
			return
		case "watch":
			runWatch(os.Args[2:])
			return
		}
	}
	runScan()
}

// scanConfig builds the pipeline configuration shared by scan and watch.
func scanConfig() pipeline.Config {
	cfg := pipeline.Config{
		ParseCacheDir: fetch.DefaultCacheDir(),
		OnFeedError: func(feed string, err error) {
			fmt.Fprintf(os.Stderr, "vanguard: warning: %s feed skipped: %v\n", feed, err)
		},
	}
	if os.Getenv("NVD_API_KEY") == "" {
		// Without a key NVD rate-limits immediately; skip it rather than fail.
		cfg.FetchNVD = func(context.Context) ([]byte, error) { return []byte("{}"), nil }
		cfg.ParseNVD = func([]byte) ([]cvmcore.Vuln, error) { return nil, nil }
	}
	return cfg
}

// runScan runs the reactive CVM loop once and prints proposals, highest score
// first.
func runScan() {
	decisions, err := pipeline.Run(context.Background(), scanConfig())
	if err != nil {
		fmt.Fprintln(os.Stderr, "vanguard:", err)
		os.Exit(1)
	}
	proposals := remediate.Build(decisions, inventory.DetectOSVersion())

	bySource := map[string]int{}
	for _, d := range decisions {
		bySource[d.Match.Vuln.Source]++
	}
	fmt.Printf("vulns: %d (by source: %v)\n", len(decisions), bySource)
	fmt.Printf("proposals: %d\n\n", len(proposals))

	const show = 20
	for i, p := range proposals {
		if i >= show {
			fmt.Printf("… and %d more\n", len(proposals)-show)
			break
		}
		fmt.Println(p.Explain())
		fmt.Println()
	}
}
