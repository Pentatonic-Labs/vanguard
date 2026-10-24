package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Pentatonic-Labs/vanguard/cvmcore/fetch"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/pipeline"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/remediate"
	"github.com/Pentatonic-Labs/vanguard/inventory"
)

// runWatch runs the reactive loop on a cadence and reports only newly-appeared
// proposals. The first run establishes a baseline; subsequent runs report
// differences.
func runWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	interval := fs.Duration("interval", time.Hour, "poll interval (e.g. 30m, 1h)")
	fs.Parse(args)

	statePath := filepath.Join(fetch.DefaultCacheDir(), "watch.json")
	seen := loadSeen(statePath)
	firstRun := !fileExists(statePath)

	for {
		start := time.Now()
		decisions, err := pipeline.Run(context.Background(), scanConfig())
		if err != nil {
			fmt.Fprintf(os.Stderr, "vanguard: %v\n", err)
			time.Sleep(*interval)
			continue
		}

		proposals := remediate.Build(decisions, inventory.DetectOSVersion())

		var fresh []remediate.Proposal
		for _, p := range proposals {
			key := p.VulnID + "|" + p.Purl
			if !seen[key] {
				fresh = append(fresh, p)
				seen[key] = true
			}
		}

		stamp := time.Now().Format(time.RFC3339)
		switch {
		case firstRun:
			fmt.Printf("[%s] baseline established: %d proposal(s) recorded; watching for changes\n", stamp, len(proposals))
			firstRun = false
		case len(fresh) > 0:
			fmt.Printf("[%s] %d new proposal(s):\n\n", stamp, len(fresh))
			for _, p := range fresh {
				fmt.Println(p.Explain())
				fmt.Println()
			}
		default:
			fmt.Printf("[%s] no new proposals\n", stamp)
		}
		_ = saveSeen(statePath, seen)

		elapsed := time.Since(start).Round(time.Millisecond)
		fmt.Printf("[%s] next check in %s (last run %s)\n\n", time.Now().Format(time.RFC3339), interval.String(), elapsed)
		time.Sleep(*interval)
	}
}

type watchState struct {
	Seen []string `json:"seen"`
}

func loadSeen(path string) map[string]bool {
	seen := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		return seen
	}
	var st watchState
	if json.Unmarshal(data, &st) == nil {
		for _, k := range st.Seen {
			seen[k] = true
		}
	}
	return seen
}

func saveSeen(path string, seen map[string]bool) error {
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	data, err := json.Marshal(watchState{Seen: keys})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
