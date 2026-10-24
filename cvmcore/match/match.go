// Package match computes which installed packages are affected by each
// vulnerability, by exact purl and by ecosystem version range.
package match

import (
	"strings"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
	"github.com/Pentatonic-Labs/vanguard/inventory"
)

// Match returns one Match per vulnerability. Each Match lists the purls of the
// installed packages that fall inside the vulnerability's affected set, either
// by exact purl or by ecosystem version range. An empty Packages slice means no
// installed package matches. Reachable is left false (a placeholder for future
// reachability analysis).
// Match returns one Match per vulnerability. release is the installed OS
// release (e.g. "24.04"); version ranges scoped to a different release are
// ignored. An empty release applies no release filter.
func Match(vulns []cvmcore.Vuln, pkgs []inventory.Package, release string) []cvmcore.Match {
	out := make([]cvmcore.Match, 0, len(vulns))
	for _, v := range vulns {
		m := cvmcore.Match{Vuln: v, Reachable: false}
		seen := make(map[string]bool)
		for _, p := range pkgs {
			if p.Purl == "" || seen[p.Purl] {
				continue
			}
			matched := purlIn(p.Purl, v.PURLs)
			if !matched {
				for _, r := range v.Affected {
					if r.Release != "" && release != "" && r.Release != release {
						continue
					}
					if r.Purl != "" && !purlMatches(p.Purl, r.Purl) {
						continue
					}
					if p.Ecosystem == r.Ecosystem && inRange(p.Version, r) {
						matched = true
						break
					}
				}
			}
			if !matched {
				matched = pkgMatchesCPE(p, v.CPEs)
			}
			if matched {
				seen[p.Purl] = true
				m.Packages = append(m.Packages, p.Purl)
			}
		}
		out = append(out, m)
	}
	return out
}

// purlIn reports whether purl is present in the given set.
func purlIn(purl string, purls []string) bool {
	for _, p := range purls {
		if p == purl {
			return true
		}
	}
	return false
}

// purlMatches reports whether two purls refer to the same package, ignoring
// version and qualifiers.
func purlMatches(a, b string) bool {
	return purlName(a) == purlName(b)
}

// purlName strips the version and qualifier suffix from a purl.
func purlName(p string) string {
	if i := strings.IndexAny(p, "@?"); i >= 0 {
		return p[:i]
	}
	return p
}

// inRange reports whether version falls inside r, using OSV semantics:
// version >= Introduced and version < Fixed. An empty Introduced means no lower
// bound (all versions); an empty Fixed means no upper bound (no fix yet). The
// comparison is Debian-aware for the "deb" ecosystem.
func inRange(version string, r cvmcore.VersionRange) bool {
	cmp := compareVersion
	if r.Ecosystem == "deb" {
		cmp = compareDebianVersion
	}
	if r.Introduced != "" && cmp(version, r.Introduced) < 0 {
		return false
	}
	if r.Fixed != "" && cmp(version, r.Fixed) >= 0 {
		return false
	}
	return true
}

// compareVersion compares two version strings segment by segment. Segments are
// split on non-alphanumeric characters; numeric segments compare numerically
// and lexical segments lexically, with a numeric segment sorting before a
// lexical one and a missing segment treated as numeric zero. This is a
// best-effort comparison: Debian epoch ("1:") and tilde ("~") ordering are
// intentionally NOT modeled.
func compareVersion(a, b string) int {
	as := splitSegments(a)
	bs := splitSegments(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		if c := segAt(as, i).compare(segAt(bs, i)); c != 0 {
			return c
		}
	}
	return 0
}

// segment is a single version component with a flag for whether it is numeric.
type segment struct {
	text    string
	numeric bool
}

// splitSegments splits a version on non-alphanumeric boundaries so that
// "1.10", "1.10.0", and "1:2.3-4" decompose into comparable components.
func splitSegments(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'))
	})
}

// segAt returns the i-th segment, or a numeric zero for a missing segment.
func segAt(segs []string, i int) segment {
	if i < len(segs) {
		s := segs[i]
		return segment{text: s, numeric: isNumeric(s)}
	}
	return segment{text: "0", numeric: true}
}

// isNumeric reports whether s is non-empty and all digits.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// compare compares two segments and returns -1, 0, or 1.
func (s segment) compare(o segment) int {
	switch {
	case s.numeric && o.numeric:
		return compareNumeric(s.text, o.text)
	case s.numeric:
		return -1
	case o.numeric:
		return 1
	default:
		return strings.Compare(s.text, o.text)
	}
}

// compareNumeric compares two numeric strings without integer overflow: leading
// zeros are trimmed, then length decides, then lexical order breaks ties.
func compareNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if a == "" {
		a = "0"
	}
	if b == "" {
		b = "0"
	}
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// cpe is a parsed CPE 2.3 URI's matching-relevant components.
type cpe struct {
	vendor  string
	product string
	version string
}

// parseCPE parses a CPE 2.3 formatted string
// (cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other)
// into its vendor, product, and version. It does not decode backslash escapes
// and is a heuristic first cut, not a full CPE implementation.
func parseCPE(s string) (cpe, bool) {
	parts := strings.Split(s, ":")
	if len(parts) < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
		return cpe{}, false
	}
	return cpe{vendor: parts[3], product: parts[4], version: parts[5]}, true
}

// pkgMatchesCPE reports whether pkg matches any of the given CPE 2.3 strings.
// CPE-to-package matching is inherently fuzzy: CPE vendor/product names do not
// map 1:1 onto package names. This is a heuristic first cut — case-insensitive
// name (exact or substring) plus a lenient version comparison.
func pkgMatchesCPE(pkg inventory.Package, cpes []string) bool {
	for _, s := range cpes {
		c, ok := parseCPE(s)
		if ok && cpeMatches(pkg, c) {
			return true
		}
	}
	return false
}

// cpeMatches reports whether pkg falls under the given parsed CPE. The name
// must match the CPE vendor or product (case-insensitive exact or substring);
// the version must then satisfy the CPE version constraint.
func cpeMatches(pkg inventory.Package, c cpe) bool {
	name := strings.ToLower(pkg.Name)
	if !cpeNameMatches(name, strings.ToLower(c.vendor)) && !cpeNameMatches(name, strings.ToLower(c.product)) {
		return false
	}
	return cpeVersionMatches(pkg.Version, c.version)
}

// cpeNameMatches reports whether a package name matches a CPE vendor/product
// token. A wildcard or missing token imposes no constraint; otherwise exact or
// substring (either direction) is accepted. Substring matching can over-match
// on very short tokens, which is accepted for this first cut.
func cpeNameMatches(name, token string) bool {
	if token == "" || token == "*" || token == "-" {
		return true
	}
	return name == token || strings.Contains(name, token) || strings.Contains(token, name)
}

// cpeVersionMatches reports a lenient version match. The CPE version field
// frequently names an affected version family (e.g. "3.0.0" meaning the 3.0.x
// line), so a package matches on exact equality, substring containment, or a
// shared major.minor prefix. A wildcard or empty version imposes no constraint.
func cpeVersionMatches(pkgVersion, cpeVersion string) bool {
	if cpeVersion == "" || cpeVersion == "*" || cpeVersion == "-" {
		return true
	}
	if pkgVersion == cpeVersion || strings.Contains(pkgVersion, cpeVersion) {
		return true
	}
	return majorMinor(pkgVersion) == majorMinor(cpeVersion)
}

// majorMinor returns the first two dotted version segments ("3.0" for
// "3.0.7"). It is used only for the fuzzy CPE version comparison.
func majorMinor(v string) string {
	segs := splitSegments(v)
	switch len(segs) {
	case 0:
		return v
	case 1:
		return segs[0]
	default:
		return segs[0] + "." + segs[1]
	}
}
