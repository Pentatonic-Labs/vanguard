// Package remediate turns triaged CVM decisions into human-actionable
// remediation proposals: what is vulnerable, what version is installed, what
// version fixes it, and what action to take.
package remediate

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// Triage tiers. A baseline on a real host tracks thousands of vuln/package
// pairs, and every one of them used to carry the same weight, so the three that
// matter were buried in the ones that cannot be acted on — mostly packages
// belonging to a kernel that is installed but never booted.
const (
	// TierActNow is a finding that is being exploited, or a critical/high
	// vulnerability reachable from a running process that has a fix: today.
	TierActNow = "act-now"
	// TierPatch is a known-fix finding worth the next patch window.
	TierPatch = "patch"
	// TierWatch is a critical/high finding with no fix known yet: monitor it.
	TierWatch = "watch"
	// TierNoise is everything else, including the packages of a kernel that is
	// not the running one.
	TierNoise = "noise"
)

// Proposal is a single remediation proposal for a triaged match.
type Proposal struct {
	VulnID    string  `json:"vuln_id"`
	Severity  string  `json:"severity"`
	CVSS      float64 `json:"cvss"`
	InKEV     bool    `json:"in_kev"`
	Reachable bool    `json:"reachable"`
	Purl      string  `json:"purl"`
	Package   string  `json:"package"`
	Installed string  `json:"installed"`
	Fixed     string  `json:"fixed"` // empty means no fix is known yet
	Action    string  `json:"action"`
	Score     float64 `json:"score"`
	Summary   string  `json:"summary,omitempty"`
	// AlsoAffected lists the other installed packages this same finding covers,
	// i.e. everything with the same vulnerability AND the same fix. A distro
	// CVE is filed against a SOURCE package, so one kernel CVE legitimately
	// matches every installed binary built from that source — the image, the
	// modules, the headers, across every kernel line on the box. Emitting one
	// proposal per binary turns a 9.8 into thirty rows, buries everything else
	// and makes the output unusable; the operator upgrades the kernel once.
	AlsoAffected []string `json:"also_affected,omitempty"`
	// Tier is how urgently this proposal needs a human: act-now, patch, watch
	// or noise. Set by Build.
	Tier string `json:"tier"`
	// StaleKernel marks a finding that only concerns a kernel other than the
	// running one. Removing that kernel package resolves it; patching the box
	// does not, so these are noise.
	StaleKernel bool `json:"stale_kernel"`
}

// HasFix reports whether a fixed version is known.
func (p Proposal) HasFix() bool { return p.Fixed != "" }

// Explain returns a plain-English remediation description.
func (p Proposal) Explain() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s", p.VulnID, p.Severity)
	if p.CVSS > 0 {
		fmt.Fprintf(&b, ", CVSS %.1f", p.CVSS)
	}
	if p.InKEV {
		b.WriteString(", actively exploited")
	}
	b.WriteString(")")
	fmt.Fprintf(&b, "\n  Package: %s (installed %s)", p.Package, p.Installed)
	if n := len(p.AlsoAffected); n > 0 {
		// One CVE, one fix, several installed binaries (a distro CVE names the
		// source package): say so rather than inventing a row per binary.
		shown := p.AlsoAffected
		if len(shown) > 3 {
			shown = shown[:3]
		}
		fmt.Fprintf(&b, "\n  Also affected (%d): %s", n, strings.Join(shown, ", "))
		if n > len(shown) {
			fmt.Fprintf(&b, " and %d more", n-len(shown))
		}
	}
	if p.Summary != "" {
		fmt.Fprintf(&b, "\n  Why it matters: %s", p.Summary)
	}
	if p.Reachable {
		b.WriteString("\n  Status: loaded by a running process")
	} else {
		b.WriteString("\n  Status: not currently loaded by any running process")
	}
	if p.HasFix() {
		fmt.Fprintf(&b, "\n  Fix: upgrade %s to >= %s", p.Package, p.Fixed)
	} else {
		fmt.Fprintf(&b, "\n  Fix: none known yet — monitor for a patch")
	}
	fmt.Fprintf(&b, "\n  Action: %s", p.Action)
	return b.String()
}

// Build converts triaged decisions into proposals, resolving each matched
// package's installed version and the fixed version from the vulnerability's
// affected range, preferring the range scoped to release. Decisions with no
// matched package are skipped; matches with no known fixed version still
// produce a proposal (HasFix is false).
func Build(decisions []cvmcore.Decision, release string) []Proposal {
	return BuildWithKernel(decisions, release, RunningKernel())
}

// BuildWithKernel is Build with the running kernel release (as `uname -r`
// prints it) supplied explicitly, so stale-kernel detection can be tested
// without owning the host's kernel.
func BuildWithKernel(decisions []cvmcore.Decision, release, runningKernel string) []Proposal {
	var out []Proposal
	// One proposal per (vulnerability, fix). Binaries from the same source
	// package carry the same fix, so they collapse into one row with the rest
	// listed in AlsoAffected.
	index := make(map[string]int, len(decisions))
	for _, d := range decisions {
		for _, purl := range d.Match.Packages {
			name, installed := splitPurl(purl)
			if name == "" {
				continue
			}
			fixed := fixedFor(d.Match.Vuln, purl, release)
			stale := isStaleKernel(name, runningKernel)
			action := string(d.Action)
			if fixed == "" {
				// No fix is known yet: there is nothing to propose, so alert the
				// operator to monitor instead.
				action = "alert"
			}
			key := d.Match.Vuln.ID + "\x00" + fixed + "\x00" + action
			if i, ok := index[key]; ok {
				if out[i].Package != name && !contains(out[i].AlsoAffected, name) {
					out[i].AlsoAffected = append(out[i].AlsoAffected, name)
				}
				if d.Score > out[i].Score {
					out[i].Score = d.Score
				}
				// A row is stale only if every package it covers is stale: if the
				// running kernel is affected too, this is still an action.
				out[i].StaleKernel = out[i].StaleKernel && stale
				continue
			}
			index[key] = len(out)
			out = append(out, Proposal{
				VulnID:      d.Match.Vuln.ID,
				Severity:    d.Match.Vuln.Severity,
				CVSS:        d.Match.Vuln.CVSS,
				InKEV:       d.Match.Vuln.InKEV,
				Reachable:   d.Match.Reachable,
				Purl:        purl,
				Package:     name,
				Installed:   installed,
				Fixed:       fixed,
				Action:      action,
				Score:       d.Score,
				Summary:     d.Match.Vuln.Summary,
				StaleKernel: stale,
			})
		}
	}
	for i := range out {
		sort.Strings(out[i].AlsoAffected)
		out[i].Tier = classify(out[i])
	}
	return out
}

// classify assigns a proposal its triage tier.
func classify(p Proposal) string {
	if p.StaleKernel {
		return TierNoise
	}
	severe := p.Severity == "critical" || p.Severity == "high"
	switch {
	case p.InKEV, severe && p.Reachable && p.HasFix():
		return TierActNow
	case p.HasFix() && (severe || p.Severity == "medium" && p.Reachable):
		return TierPatch
	case !p.HasFix() && severe:
		return TierWatch
	}
	return TierNoise
}

// kernelPackagePrefixes are the package families that carry a kernel release in
// their name.
var kernelPackagePrefixes = []string{"linux-image-", "linux-headers-", "linux-modules-"}

// RunningKernel returns the running kernel release as `uname -r` reports it, or
// "" when it cannot be determined.
func RunningKernel() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// isStaleKernel reports whether name is a kernel package belonging to a kernel
// that is not the running one. A box keeps its previous kernel line installed,
// headers and all, so one distro CVE against that kernel matches dozens of
// packages that cannot be patched away — only removed. With an unknown running
// kernel nothing is called stale: guessing would hide real findings.
func isStaleKernel(name, runningKernel string) bool {
	if runningKernel == "" {
		return false
	}
	for _, prefix := range kernelPackagePrefixes {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		return !sameKernelLine(strings.TrimPrefix(name, prefix), runningKernel)
	}
	return false
}

// sameKernelLine reports whether pkgVersion names the running kernel. Ubuntu
// ships unflavoured headers (linux-headers-6.17.0-1031) beside the flavoured
// image and modules (linux-image-6.17.0-1031-nvidia) of the same ABI, so a
// package version that is a dash-terminated prefix of the running release is
// the running kernel line, not a stale one.
func sameKernelLine(pkgVersion, runningKernel string) bool {
	return pkgVersion == runningKernel || strings.HasPrefix(runningKernel, pkgVersion+"-")
}

// contains reports whether name is already in list.
func contains(list []string, name string) bool {
	for _, s := range list {
		if s == name {
			return true
		}
	}
	return false
}

// fixedFor returns the fixed version for purl from the vuln's affected ranges,
// preferring a range scoped to release, falling back to a release-agnostic
// range, or "" if none is known.
func fixedFor(v cvmcore.Vuln, purl, release string) string {
	var fallback string
	for _, r := range v.Affected {
		if r.Fixed == "" {
			continue
		}
		if r.Purl != "" && purlName(r.Purl) != purlName(purl) {
			continue
		}
		if r.Release == release {
			return r.Fixed
		}
		if r.Release == "" && fallback == "" {
			fallback = r.Fixed
		}
	}
	return fallback
}

// splitPurl splits a purl like "pkg:deb/openssl@3.0.13" into package name and
// installed version.
func splitPurl(p string) (name, version string) {
	rest := p
	if i := strings.LastIndexByte(rest, '/'); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		return rest[:i], rest[i+1:]
	}
	return rest, ""
}

// purlName strips the version and qualifier suffix from a purl.
func purlName(p string) string {
	if i := strings.IndexAny(p, "@?"); i >= 0 {
		return p[:i]
	}
	return p
}
