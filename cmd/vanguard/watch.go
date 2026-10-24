package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Pentatonic-Labs/vanguard/cvmcore/fetch"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/pipeline"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/remediate"
	"github.com/Pentatonic-Labs/vanguard/inventory"
)

// runWatch runs the reactive loop on a cadence and reports changes: new
// findings, and findings whose fix status flipped (a patch became available,
// or a fix was withdrawn). The first run establishes a baseline.
func runWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	interval := fs.Duration("interval", time.Hour, "poll interval (e.g. 30m, 1h)")
	fs.Parse(args)

	statePath := filepath.Join(fetch.DefaultCacheDir(), "watch.json")
	prev := loadFixed(statePath)
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
		current := map[string]string{}
		byKey := map[string]remediate.Proposal{}
		for _, p := range proposals {
			key := p.VulnID + "|" + p.Purl
			current[key] = p.Fixed
			byKey[key] = p
		}

		newKeys, nowFixed, withdrawn := diffFixed(prev, current)
		stamp := time.Now().Format(time.RFC3339)

		switch {
		case firstRun:
			fmt.Printf("[%s] baseline: %d proposal(s) recorded; watching for new issues and new patches\n", stamp, len(proposals))
			firstRun = false
		default:
			for _, k := range newKeys {
				p := byKey[k]
				fmt.Printf("[%s] NEW %s in %s\n%s\n\n", stamp, p.VulnID, p.Package, p.Explain())
			}
			for _, k := range nowFixed {
				p := byKey[k]
				fmt.Printf("[%s] PATCH AVAILABLE %s in %s → upgrade to %s\n    apt-get install --only-upgrade %s=%s\n\n",
					stamp, p.VulnID, p.Package, p.Fixed, p.Package, p.Fixed)
			}
			for _, k := range withdrawn {
				p := byKey[k]
				fmt.Printf("[%s] FIX WITHDRAWN %s in %s (no longer patched)\n\n", stamp, p.VulnID, p.Package)
			}
			if len(newKeys)+len(nowFixed)+len(withdrawn) == 0 {
				fmt.Printf("[%s] no changes\n", stamp)
			}
		}
		_ = saveFixed(statePath, current)

		elapsed := time.Since(start).Round(time.Millisecond)
		fmt.Printf("[%s] next check in %s (last run %s)\n\n", time.Now().Format(time.RFC3339), interval.String(), elapsed)
		time.Sleep(*interval)
	}
}

// diffFixed classifies the transition from a previous scan's fix status (key →
// fixed version) to the current one. An empty fixed version means "no fix known
// yet".
func diffFixed(prev, current map[string]string) (newKeys, nowFixed, withdrawn []string) {
	for k, v := range current {
		old, ok := prev[k]
		if !ok {
			newKeys = append(newKeys, k)
			continue
		}
		if old == "" && v != "" {
			nowFixed = append(nowFixed, k)
		}
		if old != "" && v == "" {
			withdrawn = append(withdrawn, k)
		}
	}
	sort.Strings(newKeys)
	sort.Strings(nowFixed)
	sort.Strings(withdrawn)
	return newKeys, nowFixed, withdrawn
}

type watchState struct {
	Fixed map[string]string `json:"fixed"`
}

func loadFixed(path string) map[string]string {
	fixed := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return fixed
	}
	var st watchState
	if json.Unmarshal(data, &st) == nil {
		for k, v := range st.Fixed {
			fixed[k] = v
		}
	}
	return fixed
}

func saveFixed(path string, fixed map[string]string) error {
	data, err := json.Marshal(watchState{Fixed: fixed})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
