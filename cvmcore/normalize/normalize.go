// Package normalize de-duplicates and enriches canonical vulnerability records.
package normalize

import (
	"sort"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// Normalize de-duplicates vulnerabilities by ID, merging package/CPE/affected
// references, keeping the richest record per ID, filling severity from CVSS,
// and propagating KEV/EPSS across duplicates. It returns a slice sorted by ID
// and does not mutate the input.
func Normalize(in []cvmcore.Vuln) []cvmcore.Vuln {
	index := make(map[string]int, len(in))
	var groups [][]cvmcore.Vuln
	for _, v := range in {
		i, ok := index[v.ID]
		if !ok {
			index[v.ID] = len(groups)
			groups = append(groups, []cvmcore.Vuln{v})
			continue
		}
		groups[i] = append(groups[i], v)
	}

	out := make([]cvmcore.Vuln, 0, len(groups))
	for _, g := range groups {
		out = append(out, mergeGroup(g))
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func mergeGroup(g []cvmcore.Vuln) cvmcore.Vuln {
	baseIdx := 0
	for i := 1; i < len(g); i++ {
		if richer(g[i], g[baseIdx]) {
			baseIdx = i
		}
	}

	merged := g[baseIdx]
	for i, v := range g {
		if i == baseIdx {
			continue
		}
		merged.PURLs = unionStrings(merged.PURLs, v.PURLs)
		merged.CPEs = unionStrings(merged.CPEs, v.CPEs)
		merged.Affected = unionRanges(merged.Affected, v.Affected)
		merged.InKEV = merged.InKEV || v.InKEV
		if v.EPSS > merged.EPSS {
			merged.EPSS = v.EPSS
		}
	}

	fillSeverity(&merged)
	return merged
}

// richer reports whether a should replace b as the representative record:
// prefer a record with a CVSS score, then KEV membership, then first-seen.
func richer(a, b cvmcore.Vuln) bool {
	if (a.CVSS > 0) != (b.CVSS > 0) {
		return a.CVSS > 0
	}
	if a.InKEV != b.InKEV {
		return a.InKEV
	}
	return false
}

// fillSeverity sets Severity from CVSS when it is empty.
func fillSeverity(v *cvmcore.Vuln) {
	if v.Severity != "" {
		return
	}
	switch {
	case v.CVSS >= 9.0:
		v.Severity = "critical"
	case v.CVSS >= 7.0:
		v.Severity = "high"
	case v.CVSS >= 4.0:
		v.Severity = "medium"
	case v.CVSS > 0.0:
		v.Severity = "low"
	}
}

// unionStrings merges two string slices, dropping empty and duplicate values
// while preserving first-seen order.
func unionStrings(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if s != "" {
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	for _, s := range b {
		if s != "" {
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	return out
}

// unionRanges merges two version-range slices, dropping exact duplicates.
func unionRanges(a, b []cvmcore.VersionRange) []cvmcore.VersionRange {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]cvmcore.VersionRange, 0, len(a)+len(b))
	add := func(r cvmcore.VersionRange) {
		key := r.Ecosystem + "\x00" + r.Introduced + "\x00" + r.Fixed
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, r)
		}
	}
	for _, r := range a {
		add(r)
	}
	for _, r := range b {
		add(r)
	}
	return out
}
