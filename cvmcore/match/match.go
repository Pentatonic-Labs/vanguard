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
func Match(vulns []cvmcore.Vuln, pkgs []inventory.Package) []cvmcore.Match {
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
					if p.Ecosystem == r.Ecosystem && inRange(p.Version, r) {
						matched = true
						break
					}
				}
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

// inRange reports whether version falls inside r, using OSV semantics:
// version >= Introduced and version < Fixed. An empty Introduced means no lower
// bound (all versions); an empty Fixed means no upper bound (no fix yet).
func inRange(version string, r cvmcore.VersionRange) bool {
	if r.Introduced != "" && compareVersion(version, r.Introduced) < 0 {
		return false
	}
	if r.Fixed != "" && compareVersion(version, r.Fixed) >= 0 {
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
