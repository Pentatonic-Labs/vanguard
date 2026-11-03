package ingest

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// ChromeEcosystem is the ecosystem browser builds are collected under (see
// inventory.CollectBrowsers). Chrome Releases advisories are mapped onto it so
// a build outside the package manager can still be matched.
const ChromeEcosystem = "chromium"

// chromePURL names the browser the advisory is about.
const chromePURL = "pkg:generic/chromium"

// chromeDesktopPostTitle identifies the posts that carry desktop browser
// releases. Feeds also carry Android, ChromeOS, iOS, Extended Stable and
// Dev/Beta posts, whose versions live in different numbering and would match
// nothing here — or worse, match the wrong browser.
const chromeDesktopPostTitle = "Stable Channel Update for Desktop"

// chromeOtherProductTitles are the per-product posts that must never be read as
// a desktop stable release. "Extended Stable" is the important one: its title
// also says "Stable Channel Update for Desktop", but it describes a slower
// branch, so its fixed version would not apply to a current stable build.
var chromeOtherProductTitles = []string{
	"extended stable",
	"chromeos",
	"android",
	"ios",
}

// chromeFeed is the subset of the Atom feed this adapter reads.
type chromeFeed struct {
	Entries []chromeEntry `xml:"entry"`
}

// chromeEntry is a single Atom entry.
type chromeEntry struct {
	Title     string `xml:"title"`
	Published string `xml:"published"`
	Updated   string `xml:"updated"`
	Content   string `xml:"content"`
	Summary   string `xml:"summary"`
}

var (
	fourPartVersionRe = regexp.MustCompile(`\b(\d+\.\d+\.\d+\.\d+)\b`)
	linuxVersionRe    = regexp.MustCompile(`(?i)linux[^0-9\n]{0,40}?(\d+\.\d+\.\d+\.\d+)`)
	versionForLinuxRe = regexp.MustCompile(`(?i)(\d+\.\d+\.\d+\.\d+)[^0-9\n]{0,40}?for[^.\n]{0,30}?linux`)
	cveIDRe           = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	severityRe        = regexp.MustCompile(`(?i)\b(critical|high|medium|low)\b`)
	htmlTagRe         = regexp.MustCompile(`<[^>]*>`)
)

// ParseChromeReleases parses the Chrome Releases Atom feed into canonical
// vulnerabilities, one per CVE named in a "Stable Channel Update for Desktop"
// post.
//
// Chrome Releases is the only timely public source for browser versions: the
// distro advisories for Chromium trail it, and a build that no package manager
// maintains is fixed nowhere else. Each record carries the fixed Linux version
// of the post, so a build older than it is affected, and the in-the-wild
// statement is treated as the browser equivalent of CISA KEV — an exploited
// browser bug is the one an operator cannot defer.
func ParseChromeReleases(data []byte) ([]cvmcore.Vuln, error) {
	var feed chromeFeed
	if err := xml.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("parse Chrome Releases feed: %w", err)
	}

	var vulns []cvmcore.Vuln
	for _, entry := range feed.Entries {
		if !isChromeDesktopPost(entry.Title) {
			continue
		}
		body := stripHTML(entry.Content)
		if strings.TrimSpace(body) == "" {
			body = stripHTML(entry.Summary)
		}
		fixed := linuxVersion(body)
		if fixed == "" {
			// Without a fixed version there is nothing to compare a build
			// against, so the post cannot produce a usable record.
			continue
		}
		date := strings.TrimSpace(entry.Published)
		if date == "" {
			date = strings.TrimSpace(entry.Updated)
		}
		listed := chromeCVEs(body)
		wild, allWild := wildCVEs(body)
		for _, c := range listed {
			exploited := allWild || wild[c.id]
			status := "none"
			if exploited {
				status = "active"
			}
			summary := c.description
			if summary == "" {
				summary = "Chromium security fix"
			}
			summary = fmt.Sprintf("%s (Chrome %s for desktop, %s)", summary, fixed, date)
			vulns = append(vulns, cvmcore.Vuln{
				ID:       c.id,
				Source:   "chrome",
				PURLs:    []string{chromePURL},
				Affected: []cvmcore.VersionRange{{Purl: chromePURL, Ecosystem: ChromeEcosystem, Fixed: fixed}},
				Severity: c.severity,
				// The stable numbers are four-part versions, so the generic
				// segment comparison orders them correctly.
				InKEV:         exploited,
				ExploitStatus: status,
				Summary:       summary,
			})
		}
	}
	return vulns, nil
}

// isChromeDesktopPost reports whether a feed entry is a desktop stable release.
func isChromeDesktopPost(title string) bool {
	lower := strings.ToLower(title)
	for _, skip := range chromeOtherProductTitles {
		if strings.Contains(lower, skip) {
			return false
		}
	}
	return strings.Contains(lower, strings.ToLower(chromeDesktopPostTitle))
}

// stripHTML removes markup so the text can be scanned line by line. Feed
// content arrives as escaped HTML and line breaks survive as newlines.
func stripHTML(s string) string {
	return htmlTagRe.ReplaceAllString(s, "")
}

// linuxVersion returns the Linux fixed version named by a post. Posts word it
// either way round ("Linux: 142.0.7444.59" or "142.0.7444.60 for Windows, Mac
// and Linux"), and often give a different number per platform, so the Linux
// spelling has to win over the first number in the text.
func linuxVersion(body string) string {
	if m := linuxVersionRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	if m := versionForLinuxRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	if m := fourPartVersionRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

// chromeCVE is one CVE as described by a post.
type chromeCVE struct {
	id          string
	severity    string
	description string
}

// chromeCVEs lists the CVEs a post names, with the severity stated in front of
// each one and the description after it
// ("[1234] High CVE-2025-1111: Type Confusion in V8.").
func chromeCVEs(body string) []chromeCVE {
	var out []chromeCVE
	seen := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		ids := cveIDRe.FindAllString(line, -1)
		if len(ids) == 0 {
			continue
		}
		severity := "unknown"
		if m := severityRe.FindStringSubmatch(line); m != nil {
			severity = strings.ToLower(m[1])
		}
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, chromeCVE{id: id, severity: severity, description: cveDescription(line, id)})
		}
	}
	return out
}

// cveDescription returns the text that follows "CVE-…: " on a line, which is
// where the post names the component that was fixed.
func cveDescription(line, id string) string {
	i := strings.Index(line, id)
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line[i+len(id):]), ":"))
	if n := strings.Index(rest, "."); n >= 0 {
		rest = rest[:n]
	}
	return strings.TrimSpace(rest)
}

// wildCVEs returns the CVEs a post says are exploited in the wild, and whether
// it says so without naming any (which covers every CVE the post lists).
func wildCVEs(body string) (map[string]bool, bool) {
	ids := make(map[string]bool)
	all := false
	for _, line := range strings.Split(body, "\n") {
		if !strings.Contains(strings.ToLower(line), "in the wild") {
			continue
		}
		found := cveIDRe.FindAllString(line, -1)
		if len(found) == 0 {
			all = true
		}
		for _, id := range found {
			ids[id] = true
		}
	}
	return ids, all
}
