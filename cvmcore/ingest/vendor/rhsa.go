package vendor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// rhsaDocument is the CVRF JSON document for a Red Hat security advisory.
type rhsaDocument struct {
	DocumentTitle string `json:"document_title"`
	Tracking      struct {
		ID             string `json:"id"`
		Severity       string `json:"severity"`
		InitialRelease string `json:"initial_release_date"`
	} `json:"tracking"`
	Vulnerabilities []struct {
		CVE string `json:"cve"`
	} `json:"vulnerabilities"`
	ProductTree rhsaProductTree `json:"product_tree"`
}

// rhsaProductTree is the root of the CVRF product tree.
type rhsaProductTree struct {
	Branches []rhsaBranch `json:"branches"`
}

// rhsaBranch is a node in the CVRF product tree.
type rhsaBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Branches []rhsaBranch `json:"branches"`
}

// rhsaVersionName strips a trailing RPM version from a CVRF product_version
// name, e.g. "kernel-debug-5.14.0-362.el9_3" -> "kernel-debug".
var rhsaVersionName = regexp.MustCompile(`^(.+?)-\d`)

// ParseRHSA parses a Red Hat security advisory (CVRF JSON) into canonical
// records. Severity is advisory-level and is applied to each CVE. Package
// names are recovered on a best-effort basis from product_version branches of
// the product tree.
func ParseRHSA(data []byte) ([]cvmcore.Vuln, error) {
	var doc rhsaDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("rhsa: %w", err)
	}
	id := strings.TrimSpace(doc.Tracking.ID)
	if id == "" {
		return nil, fmt.Errorf("rhsa: advisory has no tracking id")
	}
	severity := normalizeSeverity(doc.Tracking.Severity)
	purls := rhsaPackages(doc.ProductTree)
	summary := advisorySummary(id, doc.DocumentTitle, "")

	cves := make([]string, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		cves = append(cves, v.CVE)
	}

	out := make([]cvmcore.Vuln, 0, len(cves))
	for _, cve := range dedupeStrings(cves) {
		out = append(out, cvmcore.Vuln{
			ID:       cve,
			Source:   "rhsa",
			PURLs:    purls,
			Severity: severity,
			Summary:  summary,
		})
	}
	return out, nil
}

// rhsaPackages walks the product tree collecting product_version entries and
// deriving RPM package names. It is best effort: the CVRF tree is deep and
// irregular, and a name that does not embed a version is skipped.
func rhsaPackages(tree rhsaProductTree) []string {
	var purls []string
	var walk func(rhsaBranch)
	walk = func(b rhsaBranch) {
		if b.Category == "product_version" && b.Name != "" {
			if m := rhsaVersionName.FindStringSubmatch(b.Name); m != nil {
				purls = append(purls, "pkg:rpm/"+m[1])
			}
		}
		for _, c := range b.Branches {
			walk(c)
		}
	}
	for _, b := range tree.Branches {
		walk(b)
	}
	return dedupeSorted(purls)
}
