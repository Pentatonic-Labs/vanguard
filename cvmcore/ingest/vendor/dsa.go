package vendor

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// dsaID matches the advisory identifier in a Debian security advisory, e.g.
// "DSA 5345-1" or "DSA-5345-1". It is case-sensitive so the advisory line is
// preferred over lower-case "dsa-..." URLs.
var dsaID = regexp.MustCompile(`DSA[-\s]+(\d+(?:-\d+)?)`)

// ParseDSA parses a Debian security advisory (plain text) into canonical
// records. It reads the stable header block — Package, Version, and CVE ID —
// and ignores the free-text description.
func ParseDSA(data []byte) ([]cvmcore.Vuln, error) {
	text := string(data)
	m := dsaID.FindStringSubmatch(text)
	if m == nil {
		return nil, fmt.Errorf("dsa: advisory id not found")
	}
	id := "DSA-" + m[1]

	title := ""
	if first := firstLine(text); first != "" {
		if i := strings.Index(first, "]"); i >= 0 {
			title = strings.TrimSpace(first[i+1:])
		}
	}

	headers := dsaHeaders(text)
	packages := splitList(headers["package"])
	version := strings.TrimSpace(headers["version"])
	cves := splitList(headers["cve id"])

	var purls []string
	for _, p := range packages {
		purls = append(purls, debPurl(p))
	}
	purls = dedupeSorted(purls)

	var ranges []cvmcore.VersionRange
	if version != "" {
		ranges = []cvmcore.VersionRange{{Ecosystem: "deb", Fixed: version}}
	}

	summary := advisorySummary(id, title, "")
	out := make([]cvmcore.Vuln, 0, len(cves))
	for _, cve := range cves {
		out = append(out, cvmcore.Vuln{
			ID:       cve,
			Source:   "dsa",
			PURLs:    purls,
			Affected: ranges,
			Summary:  summary,
		})
	}
	return out, nil
}

// dsaHeaders returns the lower-cased "Key: value" header lines of a DSA,
// folding indented continuation lines into the preceding header and stopping at
// the blank line that ends the header block.
func dsaHeaders(text string) map[string]string {
	headers := make(map[string]string)
	lastKey := ""
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if lastKey != "" {
				break
			}
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if ok {
			key = strings.ToLower(strings.TrimSpace(key))
			switch key {
			case "package", "version", "cve id", "debian bug":
				headers[key] = strings.TrimSpace(value)
				lastKey = key
			default:
				lastKey = ""
			}
			continue
		}
		if lastKey != "" {
			headers[lastKey] += " " + trimmed
		}
	}
	return headers
}

// splitList splits a comma-, semicolon-, or whitespace-separated list into
// trimmed, non-empty items.
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ',', ';', ' ', '\t', '\n', '\r':
			return true
		}
		return false
	})
	return dedupeStrings(fields)
}

// firstLine returns the first non-empty line of text.
func firstLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	return ""
}
