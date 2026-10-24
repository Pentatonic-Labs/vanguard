package ingest

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// osvRecord is a single OSV.dev vulnerability record.
type osvRecord struct {
	ID               string              `json:"id"`
	Summary          string              `json:"summary"`
	Details          string              `json:"details"`
	Severity         []osvSeverity       `json:"severity"`
	Affected         []osvAffected       `json:"affected"`
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
}

// osvSeverity is one entry of an OSV record's severity list. Score is either a
// numeric base score or a CVSS v3 vector string.
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// osvAffected describes one affected package in an OSV record.
type osvAffected struct {
	Package          osvPackage          `json:"package"`
	Ranges           []osvRange          `json:"ranges"`
	Versions         []string            `json:"versions"`
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
}

// osvPackage identifies an affected package.
type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// osvRange is an affected range expressed as introduced/fixed events.
type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

// osvEvent is a single range event; only introduced and fixed are used.
type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

// osvDatabaseSpecific carries free-form per-record metadata, of which only the
// qualitative severity label is used.
type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}

// osvQueryBatchResponse is the OSV.dev querybatch response, where each result
// corresponds to one queried package and carries its affected vulns.
type osvQueryBatchResponse struct {
	Results []osvQueryBatchResult `json:"results"`
}

// osvQueryBatchResult is one entry of a querybatch response.
type osvQueryBatchResult struct {
	Vulns []json.RawMessage `json:"vulns"`
}

// ParseOSVQueryBatch parses an OSV.dev querybatch response into canonical
// vulnerabilities, flattening results[].vulns[] into a single list.
func ParseOSVQueryBatch(data []byte) ([]cvmcore.Vuln, error) {
	var resp osvQueryBatchResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse OSV querybatch: %w", err)
	}
	var records []json.RawMessage
	for _, r := range resp.Results {
		records = append(records, r.Vulns...)
	}
	vulns := make([]cvmcore.Vuln, 0, len(records))
	for _, raw := range records {
		var rec osvRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("parse OSV record: %w", err)
		}
		if rec.ID == "" {
			continue
		}
		vulns = append(vulns, rec.toVuln())
	}
	return vulns, nil
}

// ParseOSVExport parses an OSV ecosystem export (a ZIP of per-vulnerability
// JSON files) into canonical vulnerabilities.
func ParseOSVExport(zipData []byte) ([]cvmcore.Vuln, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("open OSV export: %w", err)
	}
	const (
		// maxFileBytes caps a single file in the export. OSV vulnerability
		// records are tiny; this guards against a zip-bomb entry.
		maxFileBytes = 32 << 20 // 32 MiB
		// maxTotalBytes caps the total uncompressed size of the export.
		maxTotalBytes = 2 << 30 // 2 GiB
	)
	var vulns []cvmcore.Vuln
	total := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxFileBytes+1))
		rc.Close()
		if err != nil || len(data) > maxFileBytes {
			continue
		}
		total += len(data)
		if total > maxTotalBytes {
			return nil, fmt.Errorf("OSV export exceeds %d bytes uncompressed (possible zip bomb)", maxTotalBytes)
		}
		var rec osvRecord
		if err := json.Unmarshal(data, &rec); err != nil || rec.ID == "" {
			continue
		}
		vulns = append(vulns, rec.toVuln())
	}
	return vulns, nil
}

// ParseOSV parses either a single OSV record or a batch document
// ({"vulns":[...]}) into canonical vulnerabilities.
func ParseOSV(data []byte) ([]cvmcore.Vuln, error) {
	var batch struct {
		Vulns []json.RawMessage `json:"vulns"`
	}
	if err := json.Unmarshal(data, &batch); err != nil {
		return nil, fmt.Errorf("parse OSV document: %w", err)
	}
	records := batch.Vulns
	if len(records) == 0 {
		records = []json.RawMessage{json.RawMessage(data)}
	}
	vulns := make([]cvmcore.Vuln, 0, len(records))
	for _, raw := range records {
		var rec osvRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("parse OSV record: %w", err)
		}
		if rec.ID == "" {
			continue
		}
		vulns = append(vulns, rec.toVuln())
	}
	return vulns, nil
}

// toVuln converts one OSV record to the canonical record.
func (r osvRecord) toVuln() cvmcore.Vuln {
	cvss, severity := r.cvssAndSeverity()
	v := cvmcore.Vuln{
		ID:            r.ID,
		Source:        "osv",
		Severity:      severity,
		CVSS:          cvss,
		Summary:       r.Summary,
		ExploitStatus: "none",
	}
	if v.Summary == "" {
		v.Summary = r.Details
	}
	seen := make(map[string]bool)
	for _, a := range r.Affected {
		purl := ""
		if a.Package.Name != "" && a.Package.Ecosystem != "" {
			purl = "pkg:" + purlType(a.Package.Ecosystem) + "/" + a.Package.Name
			if !seen[purl] {
				seen[purl] = true
				v.PURLs = append(v.PURLs, purl)
			}
		}
		eco := ecosystemKey(a.Package.Ecosystem)
		for _, rg := range a.Ranges {
			var introduced, fixed string
			for _, ev := range rg.Events {
				// OSV uses "0" to mean "from the beginning".
				if ev.Introduced != "" && ev.Introduced != "0" && introduced == "" {
					introduced = ev.Introduced
				}
				if ev.Fixed != "" {
					fixed = ev.Fixed
				}
			}
			v.Affected = append(v.Affected, cvmcore.VersionRange{
				Purl:       purl,
				Ecosystem:  eco,
				Introduced: introduced,
				Fixed:      fixed,
			})
		}
	}
	return v
}

// cvssAndSeverity resolves the numeric CVSS and qualitative severity, preferring
// a numeric score, then a CVSS v3 vector, then database_specific labels.
func (r osvRecord) cvssAndSeverity() (float64, string) {
	for _, s := range r.Severity {
		if s.Score == "" {
			continue
		}
		if v, err := strconv.ParseFloat(s.Score, 64); err == nil {
			return v, severityFromCVSS(v)
		}
		if score, ok := cvssV3BaseScore(s.Score); ok {
			return score, severityFromCVSS(score)
		}
	}
	for _, a := range r.Affected {
		if a.DatabaseSpecific.Severity != "" {
			return 0, normalizeSeverityLabel(a.DatabaseSpecific.Severity)
		}
	}
	if r.DatabaseSpecific.Severity != "" {
		return 0, normalizeSeverityLabel(r.DatabaseSpecific.Severity)
	}
	return 0, "unknown"
}

// severityFromCVSS maps a CVSS base score to a canonical severity label.
func severityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

// normalizeSeverityLabel maps a qualitative label to the canonical vocabulary.
func normalizeSeverityLabel(label string) string {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	default:
		return "unknown"
	}
}

// ecosystemBase strips a distro suffix (e.g. "Debian:11" -> "Debian").
func ecosystemBase(ecosystem string) string {
	if i := strings.IndexByte(ecosystem, ':'); i > 0 {
		return ecosystem[:i]
	}
	return ecosystem
}

// purlType maps an OSV ecosystem name to a purl type.
func purlType(ecosystem string) string {
	switch strings.ToLower(ecosystemBase(ecosystem)) {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "go":
		return "golang"
	case "crates.io":
		return "cargo"
	case "maven":
		return "maven"
	case "nuget":
		return "nuget"
	case "packagist":
		return "composer"
	case "rubygems":
		return "gem"
	case "debian", "ubuntu":
		return "deb"
	case "alpine":
		return "apk"
	case "red hat", "rhel", "rocky linux", "almalinux", "fedora", "opensuse":
		return "rpm"
	}
	return strings.ToLower(ecosystemBase(ecosystem))
}

// ecosystemKey maps an OSV ecosystem name to the vocabulary used by
// cvmcore.VersionRange.Ecosystem.
func ecosystemKey(ecosystem string) string {
	switch strings.ToLower(ecosystemBase(ecosystem)) {
	case "npm":
		return "npm"
	case "pypi":
		return "python"
	case "go":
		return "go"
	case "crates.io":
		return "cargo"
	case "maven":
		return "maven"
	case "nuget":
		return "nuget"
	case "packagist":
		return "php"
	case "rubygems":
		return "ruby"
	case "debian", "ubuntu":
		return "deb"
	case "alpine":
		return "apk"
	case "red hat", "rhel", "rocky linux", "almalinux", "fedora", "opensuse":
		return "rpm"
	}
	return strings.ToLower(ecosystemBase(ecosystem))
}

// cvssV3BaseScore computes the CVSS v3.0/3.1 base score from a vector string.
// It reports false when the vector is not CVSS v3 or lacks required metrics.
func cvssV3BaseScore(vector string) (float64, bool) {
	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		i := strings.IndexByte(part, ':')
		if i <= 0 {
			continue
		}
		metrics[strings.ToUpper(part[:i])] = strings.ToUpper(part[i+1:])
	}

	av, okAV := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
	ac, okAC := map[string]float64{"L": 0.77, "H": 0.44}[metrics["AC"]]
	ui, okUI := map[string]float64{"N": 0.85, "R": 0.62}[metrics["UI"]]
	scope := metrics["S"]
	if !okAV || !okAC || !okUI || (scope != "U" && scope != "C") {
		return 0, false
	}

	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, okPR := prTable[metrics["PR"]]
	if !okPR {
		return 0, false
	}

	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	c, okC := cia[metrics["C"]]
	i, okI := cia[metrics["I"]]
	a, okA := cia[metrics["A"]]
	if !okC || !okI || !okA {
		return 0, false
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	if scope == "U" {
		return cvssRoundup(math.Min(impact+exploitability, 10)), true
	}
	return cvssRoundup(math.Min(1.08*(impact+exploitability), 10)), true
}

// cvssRoundup implements the CVSS v3.1 Roundup function: round up to one
// decimal place, with the integer-arithmetic form from the specification.
func cvssRoundup(in float64) float64 {
	intIn := math.Round(in * 100000)
	if math.Mod(intIn, 10000) == 0 {
		return intIn / 100000
	}
	return (math.Floor(intIn/10000) + 1) / 10
}
