// Command vanguard is the Vanguard CLI entrypoint.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/fetch"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/pipeline"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/remediate"
	"github.com/Pentatonic-Labs/vanguard/findings"
	"github.com/Pentatonic-Labs/vanguard/inventory"
	"github.com/Pentatonic-Labs/vanguard/inventory/dgx/drivers"
	"github.com/Pentatonic-Labs/vanguard/inventory/dgx/firmware"
	"github.com/Pentatonic-Labs/vanguard/inventory/dgx/ngc"
	"github.com/Pentatonic-Labs/vanguard/inventory/dgx/platform"
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
		case "scan":
			runScan(os.Args[2:])
			return
		case "inventory":
			runInventory()
			return
		case "ui":
			runUI(os.Args[2:])
			return
		case "fix":
			runFix(os.Args[2:])
			return
		}
	}
	runScan(os.Args[1:])
}

// feedFailures counts feeds that could not be fetched during this process's
// runs. A skipped feed is not "no vulnerabilities": on a host whose DNS died,
// both feeds fail, the scan finds nothing, and recording that as a baseline
// reports a permanently clean box. The watcher refuses to baseline a scan that
// lost a feed (see watch.go).
var feedFailures atomic.Int64

// scanConfig builds the pipeline configuration shared by scan and watch.
func scanConfig() pipeline.Config {
	cfg := pipeline.Config{
		ParseCacheDir: fetch.DefaultCacheDir(),
		OnFeedError: func(feed string, err error) {
			feedFailures.Add(1)
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

// runInventory prints the NVIDIA/DGX/GB10 hardware and software inventory.
// It is safe on non-DGX hosts: missing hardware is reported as zero values.
func runInventory() {
	fmt.Println("=== Vanguard hardware inventory ===")

	if report, err := drivers.Detect(); err == nil {
		fmt.Printf("NVIDIA driver : %s (%s)\n", report.Driver.Version, report.Driver.Source)
		if report.CUDA.Toolkit != "" || report.CUDA.Runtime != "" {
			fmt.Printf("CUDA          : toolkit %s, runtime %s\n", report.CUDA.Toolkit, report.CUDA.Runtime)
		}
		if report.CuDNN.Version != "" {
			fmt.Printf("cuDNN         : %s (%s)\n", report.CuDNN.Version, report.CuDNN.Source)
		}
		if report.Mismatch {
			fmt.Printf("! CUDA mismatch: %s\n", report.MismatchDetail)
		}
	} else {
		fmt.Printf("drivers       : (none detected)\n")
	}

	if infos, err := firmware.Collect(context.Background()); err == nil {
		for _, f := range infos {
			fmt.Printf("GPU           : %s (VBIOS %s, driver %s)\n", f.GPUName, f.VBIOSVersion, f.DriverVersion)
		}
		for _, d := range firmware.CheckBaseline(infos) {
			fmt.Printf("! firmware deviation: %s %s: have %q want %q\n", d.GPUName, d.Field, d.Have, d.Want)
		}
	}

	if images, err := ngc.Collect(); err == nil && len(images) > 0 {
		fmt.Printf("NGC images    : %d\n", len(images))
		for _, im := range images {
			fmt.Printf("  %s:%s\n", im.Name, im.Tag)
		}
	}
	if tv, err := ngc.DetectTritonVersion(); err == nil && tv != "" {
		fmt.Printf("Triton server : %s\n", tv)
	}

	p := platform.Collect()
	if p.SoCModel != "" {
		fmt.Printf("SoC           : %s (Grace=%v)\n", p.SoCModel, p.IsGrace)
	}
	if p.MIGMode != "" {
		fmt.Printf("MIG mode      : %s\n", p.MIGMode)
	}
	if p.HasDPU {
		fmt.Printf("DPU (ConnectX): %v\n", p.NICs)
	}
}

// writeCVMFindings persists the reactive-loop proposals as findings so the UI
// (vanguard ui) can display them alongside red-team findings.
func writeCVMFindings(proposals []remediate.Proposal) {
	list := make([]findings.Finding, 0, len(proposals))
	for _, p := range proposals {
		reach := "not-reachable"
		if p.Reachable {
			reach = "reachable"
		}
		var evidence []string
		if p.InKEV {
			evidence = append(evidence, "actively exploited (CISA KEV)")
		}
		cvss := ""
		if p.CVSS > 0 {
			cvss = fmt.Sprintf("%.1f", p.CVSS)
		}
		fixText := "No fixed version known yet — monitor for a patch and apply mitigations."
		if p.Fixed != "" {
			fixText = fmt.Sprintf("Upgrade %s from %s to %s (or later).", p.Package, p.Installed, p.Fixed)
		}
		list = append(list, findings.Finding{
			SchemaVersion: "1.0",
			ID:            "cvm-" + p.VulnID,
			RunID:         "cvm-scan",
			Source:        "cvm",
			Target:        findings.Target{Kind: "infra", Ref: p.Package},
			Vuln: findings.Vuln{
				CWE:          []string{},
				Summary:      p.VulnID + " in " + p.Package,
				Severity:     p.Severity,
				CVSS:         cvss,
				Reachability: reach,
			},
			Proof: findings.Proof{
				Repro:            "OSV/KEV feed match: " + p.VulnID,
				MachineCheckable: true,
				Evidence:         evidence,
			},
			Impact: p.Summary,
			Fix:    &findings.Fix{Suggestion: fixText, PatchRef: p.Fixed},
		})
	}
	if err := findings.Save(findings.DefaultDataDir, "cvm", list); err != nil {
		fmt.Fprintf(os.Stderr, "vanguard: warning: persist findings: %v\n", err)
	}
}

// runScan runs the reactive CVM loop once and prints proposals by triage tier.
// By default only the tiers a human can act on are listed; --all lists every
// tier, and --json prints the proposals with their tier and stale_kernel fields.
func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	showAll := fs.Bool("all", false, "list every proposal, including watch and noise")
	asJSON := fs.Bool("json", false, "print proposals as JSON")
	_ = fs.Parse(args)

	decisions, err := pipeline.Run(context.Background(), scanConfig())
	if err != nil {
		fmt.Fprintln(os.Stderr, "vanguard:", err)
		os.Exit(1)
	}
	proposals := remediate.Build(decisions, inventory.DetectOSVersion())
	writeCVMFindings(proposals)

	if *asJSON {
		enc, err := json.MarshalIndent(proposals, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "vanguard:", err)
			os.Exit(1)
		}
		fmt.Println(string(enc))
		return
	}

	bySource := map[string]int{}
	for _, d := range decisions {
		bySource[d.Match.Vuln.Source]++
	}
	fmt.Printf("vulns: %d (by source: %v)\n", len(decisions), bySource)
	fmt.Print(scanOutput(proposals, *showAll))
}

// scanOutput renders the scan's tier summary and proposal list. A baseline on a
// real host tracks thousands of vuln/package pairs, most of them about a kernel
// that is installed but never booted; listing them all buries the handful that
// need acting on, so only act-now and patch are listed unless showAll is set.
func scanOutput(proposals []remediate.Proposal, showAll bool) string {
	var b strings.Builder
	counts := map[string]int{}
	for _, p := range proposals {
		counts[p.Tier]++
	}
	fmt.Fprintf(&b, "proposals: %d\n", len(proposals))
	fmt.Fprintf(&b, "tiers: %s %d, %s %d, %s %d, %s %d\n",
		remediate.TierActNow, counts[remediate.TierActNow],
		remediate.TierPatch, counts[remediate.TierPatch],
		remediate.TierWatch, counts[remediate.TierWatch],
		remediate.TierNoise, counts[remediate.TierNoise])
	if line := oldKernelLine(proposals); line != "" {
		b.WriteString(line + "\n")
	}
	if line := rebootPendingLine(proposals); line != "" {
		b.WriteString(line + "\n")
	}
	b.WriteString("\n")

	listed := make([]remediate.Proposal, 0, len(proposals))
	for _, p := range proposals {
		if showAll || p.Tier == remediate.TierActNow || p.Tier == remediate.TierPatch {
			listed = append(listed, p)
		}
	}
	if len(listed) == 0 {
		b.WriteString("nothing to act on now\n")
		return b.String()
	}
	const show = 20
	for i, p := range listed {
		if i >= show {
			fmt.Fprintf(&b, "… and %d more\n", len(listed)-show)
			break
		}
		fmt.Fprintln(&b, p.Explain())
		b.WriteString("\n")
	}
	return b.String()
}

// oldKernelLine names, in one line, the kernel packages that belong to a kernel
// older than the running one: noise as individual findings, but worth saying
// once so the operator knows what removing them would clear.
func oldKernelLine(proposals []remediate.Proposal) string {
	var names []string
	findings := 0
	for _, p := range proposals {
		if !p.StaleKernel {
			continue
		}
		findings++
		names = append(names, p.Package)
		names = append(names, p.AlsoAffected...)
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	shown, more := names, ""
	const max = 6
	if len(shown) > max {
		shown = shown[:max]
		more = fmt.Sprintf(", and %d more", len(names)-max)
	}
	noun := "findings"
	if findings == 1 {
		noun = "finding"
	}
	return fmt.Sprintf("old kernel packages (older than the running kernel): %s%s — remove them to clear %d %s",
		strings.Join(shown, ", "), more, findings, noun)
}

// rebootPendingLine names, in one line, the kernels that are installed but not
// booted. They are not stale and must never be reported as removable: the fix
// is a reboot.
func rebootPendingLine(proposals []remediate.Proposal) string {
	seen := map[string]bool{}
	var releases []string
	for _, p := range proposals {
		if !p.PendingReboot {
			continue
		}
		for _, name := range append([]string{p.Package}, p.AlsoAffected...) {
			rel := remediate.KernelRelease(name)
			if rel == "" || seen[rel] {
				continue
			}
			seen[rel] = true
			releases = append(releases, rel)
		}
	}
	if len(releases) == 0 {
		return ""
	}
	sort.Strings(releases)
	return fmt.Sprintf("newer kernel installed but not booted (reboot pending): %s",
		strings.Join(releases, ", "))
}
