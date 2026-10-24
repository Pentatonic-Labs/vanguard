// Package vendor parses vendor security advisories — Ubuntu USN, Red Hat
// RHSA, Debian DSA, and Microsoft MSRC — into canonical cvmcore.Vuln
// records.
//
// Each parser takes the raw advisory payload (JSON or plain text) and emits
// one Vuln per CVE listed in the advisory, carrying the advisory identifier
// in Summary. Parsers are deliberately pragmatic: they read the stable fields
// of each format and ignore the rest.
package vendor

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// usnNotice is the JSON document served for a single Ubuntu security notice.
type usnNotice struct {
	ID       string                `json:"id"`
	Title    string                `json:"title"`
	Summary  string                `json:"summary"`
	CVEs     []string              `json:"cves"`
	Releases map[string]usnRelease `json:"releases"`
}

// usnRelease is one Ubuntu release affected by a notice.
type usnRelease struct {
	Packages    []usnPackage         `json:"packages"`
	AllBinaries map[string]usnBinary `json:"allbinaries"`
}

// usnPackage is a binary package fixed by a notice, with its fixed version.
type usnPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// usnBinary is an entry in the legacy allbinaries map.
type usnBinary struct {
	Version string `json:"version"`
}

// ParseUSN parses an Ubuntu security notice (JSON) into canonical records.
// Affected packages become versionless deb purls; each fixed version becomes a
// VersionRange. Release-specific disambiguation is not performed: a package
// fixed at different versions in several releases contributes one range per
// fixed version.
func ParseUSN(data []byte) ([]cvmcore.Vuln, error) {
	var n usnNotice
	if err := json.Unmarshal(data, &n); err != nil {
		return nil, fmt.Errorf("usn: %w", err)
	}
	if n.ID == "" {
		return nil, fmt.Errorf("usn: notice has no id")
	}
	purls, ranges := usnAffected(n.Releases)
	summary := advisorySummary(n.ID, n.Title, n.Summary)
	out := make([]cvmcore.Vuln, 0, len(n.CVEs))
	for _, cve := range dedupeStrings(n.CVEs) {
		out = append(out, cvmcore.Vuln{
			ID:       cve,
			Source:   "usn",
			PURLs:    purls,
			Affected: ranges,
			Summary:  summary,
		})
	}
	return out, nil
}

// usnAffected collects the affected packages and fixed-version ranges from the
// per-release package and allbinaries lists.
func usnAffected(releases map[string]usnRelease) ([]string, []cvmcore.VersionRange) {
	var purls []string
	var ranges []cvmcore.VersionRange
	for _, rel := range releases {
		for _, p := range rel.Packages {
			if p.Name == "" {
				continue
			}
			purls = append(purls, debPurl(p.Name))
			if p.Version != "" {
				ranges = append(ranges, cvmcore.VersionRange{Ecosystem: "deb", Fixed: p.Version})
			}
		}
		for name, b := range rel.AllBinaries {
			if name == "" {
				continue
			}
			purls = append(purls, debPurl(name))
			if b.Version != "" {
				ranges = append(ranges, cvmcore.VersionRange{Ecosystem: "deb", Fixed: b.Version})
			}
		}
	}
	return dedupeSorted(purls), dedupeRanges(ranges)
}

// advisorySummary renders "<advisory id>: <title>", falling back to summary
// text and then to the bare id.
func advisorySummary(id, title, summary string) string {
	desc := strings.TrimSpace(title)
	if desc == "" {
		desc = strings.TrimSpace(summary)
	}
	if desc == "" {
		return id
	}
	return id + ": " + desc
}

// debPurl returns the versionless base purl for a Debian binary package.
func debPurl(name string) string {
	return "pkg:deb/" + strings.TrimSpace(name)
}

// normalizeSeverity maps vendor severity wording (Critical, Important,
// Moderate, Low, ...) onto the canonical vocabulary. Empty input stays empty
// so a later normalize pass can derive severity from CVSS; unrecognised input
// becomes "unknown".
func normalizeSeverity(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "important", "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "unknown"
	}
}

// dedupeStrings returns the trimmed, non-empty elements of in in order,
// without duplicates.
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// dedupeSorted deduplicates and sorts a string slice for deterministic output.
func dedupeSorted(in []string) []string {
	out := dedupeStrings(in)
	sort.Strings(out)
	return out
}

// dedupeRanges removes duplicate version ranges and sorts them by Fixed.
func dedupeRanges(in []cvmcore.VersionRange) []cvmcore.VersionRange {
	seen := make(map[cvmcore.VersionRange]bool, len(in))
	out := make([]cvmcore.VersionRange, 0, len(in))
	for _, r := range in {
		if seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fixed < out[j].Fixed })
	return out
}
