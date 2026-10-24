package vendor

import (
	"strings"
	"testing"
)

// hasString reports whether list contains want.
func hasString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

const usnFixture = `{
  "id": "USN-6500-1",
  "title": "Linux kernel vulnerabilities",
  "summary": "<p>Several security issues were fixed in the Linux kernel.</p>",
  "cves": ["CVE-2023-46813", "CVE-2023-46862", "CVE-2023-46813"],
  "releases": {
    "jammy": {
      "packages": [
        {"name": "linux-image-generic", "version": "5.15.0.91.91"},
        {"name": "linux-image-5.15.0-91-generic", "version": "5.15.0-91.101"}
      ]
    },
    "focal": {
      "packages": [
        {"name": "linux-image-generic", "version": "5.4.0.167.165"}
      ]
    }
  }
}`

func TestParseUSN(t *testing.T) {
	vulns, err := ParseUSN([]byte(usnFixture))
	if err != nil {
		t.Fatalf("ParseUSN: %v", err)
	}
	if got, want := len(vulns), 2; got != want {
		t.Fatalf("len(vulns) = %d, want %d (duplicate CVE must collapse)", got, want)
	}

	first := vulns[0]
	if first.ID != "CVE-2023-46813" {
		t.Errorf("ID = %q, want %q", first.ID, "CVE-2023-46813")
	}
	if first.Source != "usn" {
		t.Errorf("Source = %q, want %q", first.Source, "usn")
	}
	if want := "USN-6500-1: Linux kernel vulnerabilities"; first.Summary != want {
		t.Errorf("Summary = %q, want %q", first.Summary, want)
	}
	for _, purl := range []string{
		"pkg:deb/linux-image-generic",
		"pkg:deb/linux-image-5.15.0-91-generic",
	} {
		if !hasString(first.PURLs, purl) {
			t.Errorf("PURLs %v missing %q", first.PURLs, purl)
		}
	}
	if got, want := len(first.Affected), 3; got != want {
		t.Fatalf("len(Affected) = %d, want %d (%v)", got, want, first.Affected)
	}
	var fixed []string
	for _, r := range first.Affected {
		if r.Ecosystem != "deb" {
			t.Errorf("Affected ecosystem = %q, want deb", r.Ecosystem)
		}
		fixed = append(fixed, r.Fixed)
	}
	for _, want := range []string{"5.15.0-91.101", "5.15.0.91.91", "5.4.0.167.165"} {
		if !hasString(fixed, want) {
			t.Errorf("Affected fixed versions %v missing %q", fixed, want)
		}
	}
}

func TestParseUSNNoID(t *testing.T) {
	if _, err := ParseUSN([]byte(`{"title":"x","cves":["CVE-1"]}`)); err == nil {
		t.Fatal("ParseUSN returned nil error for a notice with no id")
	}
}

const rhsaFixture = `{
  "document_title": "Red Hat Security Advisory: kernel security update",
  "tracking": {
    "id": "RHSA-2023:1234",
    "severity": "Important",
    "initial_release_date": "2023-11-21T00:00:00Z"
  },
  "vulnerabilities": [
    {"cve": "CVE-2023-46813"},
    {"cve": "CVE-2023-46862"}
  ],
  "product_tree": {
    "branches": [
      {
        "category": "product_name",
        "name": "Red Hat Enterprise Linux 9",
        "branches": [
          {"category": "product_version", "name": "kernel-5.14.0-362.8.1.el9_3"},
          {"category": "product_version", "name": "kernel-debug-5.14.0-362.8.1.el9_3"}
        ]
      }
    ]
  }
}`

func TestParseRHSA(t *testing.T) {
	vulns, err := ParseRHSA([]byte(rhsaFixture))
	if err != nil {
		t.Fatalf("ParseRHSA: %v", err)
	}
	if got, want := len(vulns), 2; got != want {
		t.Fatalf("len(vulns) = %d, want %d", got, want)
	}
	first := vulns[0]
	if first.ID != "CVE-2023-46813" || first.Source != "rhsa" {
		t.Errorf("ID/Source = %q/%q", first.ID, first.Source)
	}
	if first.Severity != "high" {
		t.Errorf("Severity = %q, want high (Important)", first.Severity)
	}
	if want := "RHSA-2023:1234: Red Hat Security Advisory: kernel security update"; first.Summary != want {
		t.Errorf("Summary = %q, want %q", first.Summary, want)
	}
	for _, purl := range []string{"pkg:rpm/kernel", "pkg:rpm/kernel-debug"} {
		if !hasString(first.PURLs, purl) {
			t.Errorf("PURLs %v missing %q", first.PURLs, purl)
		}
	}
}

func TestParseRHSAInvalid(t *testing.T) {
	if _, err := ParseRHSA([]byte(`{"document_title":"x"}`)); err == nil {
		t.Fatal("ParseRHSA returned nil error for an advisory with no tracking id")
	}
}

const dsaFixture = `[ DSA 5345-1 ] linux security update
    https://www.debian.org/security/2023/dsa-5345

Package        : linux
Version        : 5.10.197-1
CVE ID         : CVE-2023-46813 CVE-2023-46862
Debian Bug     : 1055111 1055112

Description
-----------
Several vulnerabilities were discovered in the Linux kernel.
`

func TestParseDSA(t *testing.T) {
	vulns, err := ParseDSA([]byte(dsaFixture))
	if err != nil {
		t.Fatalf("ParseDSA: %v", err)
	}
	if got, want := len(vulns), 2; got != want {
		t.Fatalf("len(vulns) = %d, want %d", got, want)
	}
	first := vulns[0]
	if first.ID != "CVE-2023-46813" || first.Source != "dsa" {
		t.Errorf("ID/Source = %q/%q", first.ID, first.Source)
	}
	if want := "DSA-5345-1: linux security update"; first.Summary != want {
		t.Errorf("Summary = %q, want %q", first.Summary, want)
	}
	if len(first.PURLs) != 1 || first.PURLs[0] != "pkg:deb/linux" {
		t.Errorf("PURLs = %v, want [pkg:deb/linux]", first.PURLs)
	}
	if len(first.Affected) != 1 || first.Affected[0].Ecosystem != "deb" || first.Affected[0].Fixed != "5.10.197-1" {
		t.Errorf("Affected = %+v, want one deb range fixed at 5.10.197-1", first.Affected)
	}
}

func TestParseDSAInvalid(t *testing.T) {
	if _, err := ParseDSA([]byte("no advisory identifier here")); err == nil {
		t.Fatal("ParseDSA returned nil error with no DSA id")
	}
}

const msrcFixture = `{
  "DocumentTitle": {"Value": "November 2023 Security Updates"},
  "Tracking": {"ID": {"Value": "2023-Nov"}},
  "Vulnerability": [
    {
      "CVE": "CVE-2023-36049",
      "Title": {"Value": "Windows Kernel Elevation of Privilege Vulnerability"},
      "CVSSScoreSets": [{"BaseScore": "7.8"}],
      "Threats": [
        {"Type": 0, "Description": {"Value": "Elevation of Privilege"}},
        {"Type": 3, "Description": {"Value": "Important"}}
      ]
    },
    {
      "CVE": "CVE-2023-36050",
      "Title": {"Value": ".NET Remote Code Execution Vulnerability"},
      "CVSSScoreSets": [{"BaseScore": "9.8"}],
      "Threats": [{"Type": 3, "Description": {"Value": "Critical"}}]
    },
    {"CVE": "", "Title": {"Value": "no cve"}}
  ]
}`

func TestParseMSRC(t *testing.T) {
	vulns, err := ParseMSRC([]byte(msrcFixture))
	if err != nil {
		t.Fatalf("ParseMSRC: %v", err)
	}
	if got, want := len(vulns), 2; got != want {
		t.Fatalf("len(vulns) = %d, want %d (empty CVE must be skipped)", got, want)
	}

	first := vulns[0]
	if first.ID != "CVE-2023-36049" || first.Source != "msrc" {
		t.Errorf("ID/Source = %q/%q", first.ID, first.Source)
	}
	if first.Severity != "high" {
		t.Errorf("Severity = %q, want high (Important)", first.Severity)
	}
	if first.CVSS != 7.8 {
		t.Errorf("CVSS = %v, want 7.8", first.CVSS)
	}
	if want := "2023-Nov: Windows Kernel Elevation of Privilege Vulnerability"; first.Summary != want {
		t.Errorf("Summary = %q, want %q", first.Summary, want)
	}

	second := vulns[1]
	if second.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", second.Severity)
	}
	if second.CVSS != 9.8 {
		t.Errorf("CVSS = %v, want 9.8", second.CVSS)
	}
}

func TestParseMSRCInvalid(t *testing.T) {
	if _, err := ParseMSRC([]byte(`{"Vulnerability":[]}`)); err == nil {
		t.Fatal("ParseMSRC returned nil error for a release with no tracking id")
	}
}

func TestAdvisorySummaryFallsBackToID(t *testing.T) {
	if got, want := advisorySummary("X-1", "", ""), "X-1"; got != want {
		t.Errorf("advisorySummary = %q, want %q", got, want)
	}
	if got, want := advisorySummary("X-1", "", "desc"), "X-1: desc"; got != want {
		t.Errorf("advisorySummary = %q, want %q", got, want)
	}
	if !strings.HasPrefix(advisorySummary("X-1", "t", "s"), "X-1: t") {
		t.Errorf("advisorySummary should prefer title")
	}
}
