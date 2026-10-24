package ingest

import (
	"encoding/json"
	"fmt"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// nvdResponse is the NVD 2.0 API response document.
type nvdResponse struct {
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

// nvdVulnerability wraps a single CVE as returned by NVD 2.0.
type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

// nvdCVE is the CVE payload of an NVD 2.0 record.
type nvdCVE struct {
	ID             string             `json:"id"`
	Descriptions   []nvdDescription   `json:"descriptions"`
	Metrics        nvdMetrics         `json:"metrics"`
	Configurations []nvdConfiguration `json:"configurations"`
}

// nvdDescription is one localized description of a CVE.
type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// nvdMetrics holds the CVSS metric sets NVD may attach to a CVE.
type nvdMetrics struct {
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV40 []nvdCVSSMetric `json:"cvssMetricV40"`
}

// nvdCVSSMetric is a single CVSS scoring entry.
type nvdCVSSMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

// nvdCVSSData is the scoring data of an nvdCVSSMetric.
type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// nvdConfiguration describes the CPE applicability of a CVE.
type nvdConfiguration struct {
	Nodes []nvdNode `json:"nodes"`
}

// nvdNode is a single node of a configuration tree.
type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

// nvdCPEMatch is one CPE applicability statement.
type nvdCPEMatch struct {
	Criteria   string `json:"criteria"`
	Vulnerable *bool  `json:"vulnerable"`
}

// ParseNVD parses an NVD 2.0 API response into canonical vulnerabilities.
func ParseNVD(data []byte) ([]cvmcore.Vuln, error) {
	var resp nvdResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse NVD response: %w", err)
	}
	vulns := make([]cvmcore.Vuln, 0, len(resp.Vulnerabilities))
	for _, item := range resp.Vulnerabilities {
		c := item.CVE
		if c.ID == "" {
			continue
		}
		cvss, severity := nvdCVSS(c.Metrics)
		v := cvmcore.Vuln{
			ID:            c.ID,
			Source:        "nvd",
			Severity:      severity,
			CVSS:          cvss,
			Summary:       englishDescription(c.Descriptions),
			ExploitStatus: "none",
		}
		for _, cfg := range c.Configurations {
			for _, node := range cfg.Nodes {
				for _, match := range node.CPEMatch {
					if match.Criteria == "" {
						continue
					}
					if match.Vulnerable != nil && !*match.Vulnerable {
						continue
					}
					v.CPEs = append(v.CPEs, match.Criteria)
				}
			}
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// nvdCVSS returns the CVSS base score and severity, preferring CVSS v3.1 over
// v4.0 and falling back to deriving a label from the numeric score.
func nvdCVSS(m nvdMetrics) (float64, string) {
	for _, set := range [][]nvdCVSSMetric{m.CVSSMetricV31, m.CVSSMetricV40} {
		for _, metric := range set {
			d := metric.CVSSData
			if d.BaseScore <= 0 {
				continue
			}
			if label := normalizeSeverityLabel(d.BaseSeverity); label != "unknown" {
				return d.BaseScore, label
			}
			return d.BaseScore, severityFromCVSS(d.BaseScore)
		}
	}
	return 0, "unknown"
}

// englishDescription returns the English description, else the first non-empty.
func englishDescription(descs []nvdDescription) string {
	fallback := ""
	for _, d := range descs {
		if d.Value == "" {
			continue
		}
		if d.Lang == "en" {
			return d.Value
		}
		if fallback == "" {
			fallback = d.Value
		}
	}
	return fallback
}
