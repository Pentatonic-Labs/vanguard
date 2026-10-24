// Package ingest adapts external vulnerability feeds (CISA KEV, OSV.dev, NVD,
// and vendor advisories) into the canonical cvmcore.Vuln record.
package ingest

import (
	"encoding/json"
	"fmt"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// kevCatalog is the CISA Known Exploited Vulnerabilities catalog document.
type kevCatalog struct {
	Vulnerabilities []kevItem `json:"vulnerabilities"`
}

// kevItem is a single entry in the CISA KEV catalog.
type kevItem struct {
	CVEID             string `json:"cveID"`
	VulnerabilityName string `json:"vulnerabilityName"`
	ShortDescription  string `json:"shortDescription"`
	RansomwareUse     string `json:"knownRansomwareCampaignUse"`
}

// ParseKEV parses a CISA KEV catalog document into canonical vulnerabilities.
// Every KEV entry is by definition actively exploited, so InKEV is set and
// ExploitStatus is "active".
func ParseKEV(data []byte) ([]cvmcore.Vuln, error) {
	var cat kevCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil, fmt.Errorf("parse KEV catalog: %w", err)
	}
	vulns := make([]cvmcore.Vuln, 0, len(cat.Vulnerabilities))
	for _, item := range cat.Vulnerabilities {
		if item.CVEID == "" {
			continue
		}
		summary := item.ShortDescription
		if summary == "" {
			summary = item.VulnerabilityName
		}
		vulns = append(vulns, cvmcore.Vuln{
			ID:            item.CVEID,
			Source:        "kev",
			Severity:      "unknown",
			InKEV:         true,
			ExploitStatus: "active",
			Summary:       summary,
		})
	}
	return vulns, nil
}
