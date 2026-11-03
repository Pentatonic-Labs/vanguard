package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Pentatonic-Labs/vanguard/posture"
)

// runPosture runs the posture checks. By default it runs the on-host runtime
// checks and every SaaS check whose target is configured in the environment
// (VANGUARD_GITHUB_ORG, VANGUARD_CLOUDFLARE_ZONE, VANGUARD_ENTRA_TENANT);
// --local-only restricts it to the on-host checks. It exits non-zero when a
// check fails, so it can gate a scheduled job.
func runPosture(args []string) {
	fs := flag.NewFlagSet("posture", flag.ExitOnError)
	localOnly := fs.Bool("local-only", false, "run only the on-host runtime checks")
	asJSON := fs.Bool("json", false, "print results as JSON")
	root := fs.String("root", "/", "filesystem root the on-host checks read (for inspecting a mounted snapshot)")
	fs.Parse(args)

	results := posture.NewRuntime(*root).Results(context.Background())
	if !*localOnly {
		for _, checker := range saasCheckers() {
			res, err := checker.Check(context.Background())
			if err != nil {
				fmt.Fprintf(os.Stderr, "vanguard: posture: %v\n", err)
				continue
			}
			results = append(results, res...)
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(os.Stderr, "vanguard: posture: %v\n", err)
			os.Exit(1)
		}
		return
	}

	failing := 0
	for _, r := range results {
		status := "ok  "
		severity := ""
		if !r.Pass {
			status = "FAIL"
			failing++
			if r.Severity != "" {
				severity = " [" + r.Severity + "]"
			}
		}
		fmt.Printf("%s %-10s %-26s%s %s\n", status, r.Service, r.Check, severity, r.Detail)
		if !r.Pass && r.Fix != "" {
			fmt.Printf("     fix: %s\n", r.Fix)
		}
	}
	if failing > 0 {
		fmt.Printf("\n%d check(s) failing\n", failing)
		os.Exit(1)
	}
}

// saasCheckers returns the remote checkers whose target is configured. A
// checker whose token is unset reports "not configured" rather than an error.
func saasCheckers() []posture.Checker {
	var checkers []posture.Checker
	if org := os.Getenv("VANGUARD_GITHUB_ORG"); org != "" {
		checkers = append(checkers, posture.NewGitHubChecker(org))
	}
	if zone := os.Getenv("VANGUARD_CLOUDFLARE_ZONE"); zone != "" {
		checkers = append(checkers, posture.NewCloudflareChecker(zone))
	}
	if tenant := os.Getenv("VANGUARD_ENTRA_TENANT"); tenant != "" {
		checkers = append(checkers, posture.NewEntraChecker(tenant))
	}
	if os.Getenv("VANGUARD_LINEAR_TOKEN") != "" {
		checkers = append(checkers, posture.NewLinearChecker())
	}
	return checkers
}
