// vanguard posture — read-only security-posture checks.
//
// Always runs the local Tailscale checks (mapping to the Tailworm findings),
// which need no credentials and mutate nothing. SaaS checks (GitHub / Entra /
// Cloudflare / Linear) run only when their env token is set and, where a
// target is required, the corresponding flag is given.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Pentatonic-Labs/vanguard/posture"
)

func runPosture(args []string) {
	fs := flag.NewFlagSet("posture", flag.ExitOnError)
	githubOrg := fs.String("github-org", "", "GitHub org to check (requires VANGUARD_GITHUB_TOKEN)")
	entraTenant := fs.String("entra-tenant", "", "Entra tenant ID or domain to check (requires VANGUARD_ENTRA_TOKEN)")
	cloudflareZone := fs.String("cloudflare-zone", "", "Cloudflare zone ID to check (requires VANGUARD_CLOUDFLARE_TOKEN)")
	fs.Parse(args)

	ctx := context.Background()
	var results []posture.Result

	add := func(rs []posture.Result, err error) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "vanguard: posture: %v\n", err)
			return
		}
		results = append(results, rs...)
	}

	// Tailscale always runs: read-only local checks, no credentials needed.
	add(posture.NewTailscaleChecker().Check(ctx))

	if *githubOrg != "" {
		add(posture.NewGitHubChecker(*githubOrg).Check(ctx))
	}
	if *entraTenant != "" {
		add(posture.NewEntraChecker(*entraTenant).Check(ctx))
	}
	if *cloudflareZone != "" {
		add(posture.NewCloudflareChecker(*cloudflareZone).Check(ctx))
	}
	// Linear needs no target argument; run it when a token is present so a
	// missing token doesn't add noise, and so the "not checkable over GET"
	// limitation is only shown when the operator actually configured it.
	if os.Getenv("VANGUARD_LINEAR_TOKEN") != "" {
		add(posture.NewLinearChecker().Check(ctx))
	}

	printPosture(results)
}

func printPosture(results []posture.Result) {
	if len(results) == 0 {
		fmt.Println("no posture checks run")
		return
	}

	// Preserve first-appearance service order while grouping results.
	var services []string
	seen := map[string]bool{}
	for _, r := range results {
		if !seen[r.Service] {
			seen[r.Service] = true
			services = append(services, r.Service)
		}
	}

	for _, svc := range services {
		fmt.Printf("\n== %s ==\n", svc)
		for _, r := range results {
			if r.Service != svc {
				continue
			}
			mark := "PASS"
			if !r.Pass {
				mark = "FAIL"
			}
			fmt.Printf("[%s] %s\n      %s\n", mark, r.Check, r.Detail)
		}
	}
}
