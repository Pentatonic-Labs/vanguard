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
		case "inventory":
			runInventory()
			return
		case "ui":
			runUI(os.Args[2:])
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
			Fix:    &findings.Fix{Suggestion: fixText},
		})
	}
	if err := findings.Save(findings.DefaultDataDir, "cvm", list); err != nil {
		fmt.Fprintf(os.Stderr, "vanguard: warning: persist findings: %v\n", err)
	}
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
	writeCVMFindings(proposals)

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
