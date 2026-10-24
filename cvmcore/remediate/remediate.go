// Package remediate turns triaged CVM decisions into human-actionable
// remediation proposals: what is vulnerable, what version is installed, what
// version fixes it, and what action to take.
package remediate

import (
	"fmt"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// Proposal is a single remediation proposal for a triaged match.
type Proposal struct {
	VulnID    string  `json:"vuln_id"`
	Severity  string  `json:"severity"`
	CVSS      float64 `json:"cvss"`
	InKEV     bool    `json:"in_kev"`
	Purl      string  `json:"purl"`
	Package   string  `json:"package"`
	Installed string  `json:"installed"`
	Fixed     string  `json:"fixed"` // empty means no fix is known yet
	Action    string  `json:"action"`
	Score     float64 `json:"score"`
	Summary   string  `json:"summary,omitempty"`
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
	if p.Summary != "" {
		fmt.Fprintf(&b, "\n  Why it matters: %s", p.Summary)
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
	var out []Proposal
	for _, d := range decisions {
		for _, purl := range d.Match.Packages {
			name, installed := splitPurl(purl)
			if name == "" {
				continue
			}
			fixed := fixedFor(d.Match.Vuln, purl, release)
			action := string(d.Action)
			if fixed == "" {
				// No fix is known yet: there is nothing to propose, so alert the
				// operator to monitor instead.
				action = "alert"
			}
			out = append(out, Proposal{
				VulnID:    d.Match.Vuln.ID,
				Severity:  d.Match.Vuln.Severity,
				CVSS:      d.Match.Vuln.CVSS,
				InKEV:     d.Match.Vuln.InKEV,
				Purl:      purl,
				Package:   name,
				Installed: installed,
				Fixed:     fixed,
				Action:    action,
				Score:     d.Score,
				Summary:   d.Match.Vuln.Summary,
			})
		}
	}
	return out
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
