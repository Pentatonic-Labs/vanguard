package vendor

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// msrcValue is a CVRF "Value" wrapper object.
type msrcValue struct {
	Value string `json:"Value"`
}

// msrcThreat is a CVRF threat entry. Type 3 carries the severity.
type msrcThreat struct {
	Type        int       `json:"Type"`
	Description msrcValue `json:"Description"`
}

// msrcScore is a CVRF CVSS score set.
type msrcScore struct {
	BaseScore string `json:"BaseScore"`
}

// msrcVulnerability is one vulnerability entry in an MSRC release.
type msrcVulnerability struct {
	CVE           string       `json:"CVE"`
	Title         msrcValue    `json:"Title"`
	CVSSScoreSets []msrcScore  `json:"CVSSScoreSets"`
	Threats       []msrcThreat `json:"Threats"`
}

// msrcDocument is the CVRF JSON document published by the Microsoft Security
// Response Center for a monthly security release.
type msrcDocument struct {
	DocumentTitle msrcValue `json:"DocumentTitle"`
	Tracking      struct {
		ID msrcValue `json:"ID"`
	} `json:"Tracking"`
	Vulnerability []msrcVulnerability `json:"Vulnerability"`
}

// ParseMSRC parses a Microsoft MSRC CVRF document into canonical records. Each
// vulnerability entry becomes one Vuln carrying its CVE, title, severity
// (CVRF threat type 3) and base CVSS score. This document shape carries no
// package inventory, so PURLs are left empty.
func ParseMSRC(data []byte) ([]cvmcore.Vuln, error) {
	var doc msrcDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("msrc: %w", err)
	}
	id := strings.TrimSpace(doc.Tracking.ID.Value)
	if id == "" {
		return nil, fmt.Errorf("msrc: release has no tracking id")
	}
	releaseTitle := strings.TrimSpace(doc.DocumentTitle.Value)

	out := make([]cvmcore.Vuln, 0, len(doc.Vulnerability))
	for _, v := range doc.Vulnerability {
		cve := strings.TrimSpace(v.CVE)
		if cve == "" {
			continue
		}
		title := strings.TrimSpace(v.Title.Value)
		if title == "" {
			title = releaseTitle
		}
		out = append(out, cvmcore.Vuln{
			ID:       cve,
			Source:   "msrc",
			Severity: msrcSeverity(v.Threats),
			CVSS:     firstBaseScore(v.CVSSScoreSets),
			Summary:  advisorySummary(id, title, ""),
		})
	}
	return out, nil
}

// msrcSeverity returns the severity carried by a CVRF threat of type 3.
func msrcSeverity(threats []msrcThreat) string {
	for _, t := range threats {
		if t.Type == 3 {
			return normalizeSeverity(t.Description.Value)
		}
	}
	return ""
}

// firstBaseScore returns the first parseable base CVSS score, or 0.
func firstBaseScore(scores []msrcScore) float64 {
	for _, s := range scores {
		if v, err := strconv.ParseFloat(strings.TrimSpace(s.BaseScore), 64); err == nil {
			return v
		}
	}
	return 0
}
