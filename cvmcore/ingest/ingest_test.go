package ingest

import (
	"math"
	"testing"
)

const kevFixture = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2024.01.01",
  "count": 2,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
      "shortDescription": "Apache Log4j2 contains a vulnerability that allows remote code execution.",
      "knownRansomwareCampaignUse": "Known"
    },
    {
      "cveID": "CVE-2023-0001",
      "vulnerabilityName": "Example"
    }
  ]
}`

func TestParseKEV(t *testing.T) {
	vulns, err := ParseKEV([]byte(kevFixture))
	if err != nil {
		t.Fatalf("ParseKEV: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("got %d vulns, want 2", len(vulns))
	}
	first := vulns[0]
	if first.ID != "CVE-2021-44228" {
		t.Errorf("ID = %q, want CVE-2021-44228", first.ID)
	}
	if first.Source != "kev" {
		t.Errorf("Source = %q, want kev", first.Source)
	}
	if !first.InKEV {
		t.Error("InKEV = false, want true")
	}
	if first.ExploitStatus != "active" {
		t.Errorf("ExploitStatus = %q, want active", first.ExploitStatus)
	}
	if first.Summary != "Apache Log4j2 contains a vulnerability that allows remote code execution." {
		t.Errorf("Summary = %q", first.Summary)
	}
	// An entry without a shortDescription falls back to vulnerabilityName.
	if vulns[1].Summary != "Example" {
		t.Errorf("fallback Summary = %q, want Example", vulns[1].Summary)
	}
}

func TestParseKEVInvalidJSON(t *testing.T) {
	if _, err := ParseKEV([]byte("{")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

const osvSingleFixture = `{
  "id": "GHSA-jfh8-c2jp-5v3q",
  "summary": "Remote code execution in log4j",
  "details": "long details",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
  "affected": [
    {
      "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
      "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}
      ]
    }
  ]
}`

func TestParseOSVSingleWithVector(t *testing.T) {
	vulns, err := ParseOSV([]byte(osvSingleFixture))
	if err != nil {
		t.Fatalf("ParseOSV: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("got %d vulns, want 1", len(vulns))
	}
	v := vulns[0]
	if v.ID != "GHSA-jfh8-c2jp-5v3q" || v.Source != "osv" {
		t.Errorf("ID/Source = %q/%q", v.ID, v.Source)
	}
	if math.Abs(v.CVSS-10.0) > 0.01 {
		t.Errorf("CVSS = %v, want 10.0", v.CVSS)
	}
	if v.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", v.Severity)
	}
	if len(v.PURLs) != 1 || v.PURLs[0] != "pkg:maven/org.apache.logging.log4j:log4j-core" {
		t.Errorf("PURLs = %v", v.PURLs)
	}
	if len(v.Affected) != 1 {
		t.Fatalf("Affected len = %d, want 1", len(v.Affected))
	}
	r := v.Affected[0]
	if r.Ecosystem != "maven" || r.Introduced != "2.0" || r.Fixed != "2.15.0" {
		t.Errorf("range = %+v", r)
	}
}

const osvBatchFixture = `{
  "vulns": [
    {"id": "OSV-1", "summary": "a", "database_specific": {"severity": "HIGH"}},
    {"id": "OSV-2", "summary": "b", "severity": [{"type": "CVSS_V3", "score": "9.8"}]},
    {"summary": "missing id is skipped"}
  ]
}`

func TestParseOSVBatch(t *testing.T) {
	vulns, err := ParseOSV([]byte(osvBatchFixture))
	if err != nil {
		t.Fatalf("ParseOSV: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("got %d vulns, want 2 (record without id skipped)", len(vulns))
	}
	if vulns[0].Severity != "high" {
		t.Errorf("severity from database_specific = %q, want high", vulns[0].Severity)
	}
	if math.Abs(vulns[1].CVSS-9.8) > 0.01 || vulns[1].Severity != "critical" {
		t.Errorf("numeric score: CVSS=%v severity=%q", vulns[1].CVSS, vulns[1].Severity)
	}
}

const osvQueryBatchFixture = `{
  "results": [
    {"vulns": [
      {"id": "OSV-Q1", "summary": "first", "database_specific": {"severity": "HIGH"}},
      {"summary": "missing id skipped"}
    ]},
    {"vulns": [
      {"id": "OSV-Q2", "severity": [{"type": "CVSS_V3", "score": "9.8"}]}
    ]}
  ]
}`

func TestParseOSVQueryBatch(t *testing.T) {
	vulns, err := ParseOSVQueryBatch([]byte(osvQueryBatchFixture))
	if err != nil {
		t.Fatalf("ParseOSVQueryBatch: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("got %d vulns, want 2 (id-less record skipped)", len(vulns))
	}
	if vulns[0].ID != "OSV-Q1" || vulns[0].Source != "osv" {
		t.Errorf("vulns[0] = %q/%q, want OSV-Q1/osv", vulns[0].ID, vulns[0].Source)
	}
	if vulns[0].Severity != "high" {
		t.Errorf("severity from database_specific = %q, want high", vulns[0].Severity)
	}
	if math.Abs(vulns[1].CVSS-9.8) > 0.01 {
		t.Errorf("vulns[1].CVSS = %v, want 9.8", vulns[1].CVSS)
	}
}

func TestParseOSVIntroducedZeroIsAllVersions(t *testing.T) {
	const fixture = `{
	  "id": "OSV-3",
	  "affected": [{"package": {"ecosystem": "PyPI", "name": "example"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}]
	}`
	vulns, err := ParseOSV([]byte(fixture))
	if err != nil {
		t.Fatalf("ParseOSV: %v", err)
	}
	if len(vulns) != 1 || len(vulns[0].Affected) != 1 {
		t.Fatalf("unexpected shape: %+v", vulns)
	}
	r := vulns[0].Affected[0]
	if r.Ecosystem != "python" || r.Introduced != "" || r.Fixed != "1.2.3" {
		t.Errorf("range = %+v, want python/''/1.2.3", r)
	}
	if len(vulns[0].PURLs) != 1 || vulns[0].PURLs[0] != "pkg:pypi/example" {
		t.Errorf("PURLs = %v", vulns[0].PURLs)
	}
}

const nvdFixture = `{
  "resultsPerPage": 1,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-1234",
        "descriptions": [
          {"lang": "es", "value": "spanish"},
          {"lang": "en", "value": "english description"}
        ],
        "metrics": {
          "cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
          ]
        },
        "configurations": [
          {"nodes": [
            {"cpeMatch": [
              {"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "vulnerable": true},
              {"criteria": "cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*", "vulnerable": false}
            ]}
          ]}
        ]
      }
    }
  ]
}`

func TestParseNVD(t *testing.T) {
	vulns, err := ParseNVD([]byte(nvdFixture))
	if err != nil {
		t.Fatalf("ParseNVD: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("got %d vulns, want 1", len(vulns))
	}
	v := vulns[0]
	if v.ID != "CVE-2024-1234" || v.Source != "nvd" {
		t.Errorf("ID/Source = %q/%q", v.ID, v.Source)
	}
	if math.Abs(v.CVSS-9.8) > 0.01 {
		t.Errorf("CVSS = %v, want 9.8", v.CVSS)
	}
	if v.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", v.Severity)
	}
	if v.Summary != "english description" {
		t.Errorf("Summary = %q", v.Summary)
	}
	// Only the vulnerable CPE is kept.
	if len(v.CPEs) != 1 || v.CPEs[0] != "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*" {
		t.Errorf("CPEs = %v", v.CPEs)
	}
}

func TestParseNVDInvalidJSON(t *testing.T) {
	if _, err := ParseNVD([]byte("null")); err != nil {
		t.Fatalf("null should parse to an empty response, got %v", err)
	}
	if _, err := ParseNVD([]byte("{")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestCVSSV3BaseScore(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		want   float64
		ok     bool
	}{
		{"log4shell changed scope", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, true},
		{"network no auth", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"authenticated", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, true},
		{"local authenticated", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, true},
		{"no impact", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, true},
		{"not a vector", "not-a-vector", 0, false},
		{"missing metrics", "CVSS:3.1/AV:N/AC:L", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := cvssV3BaseScore(tc.vector)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if tc.ok && math.Abs(got-tc.want) > 0.001 {
				t.Errorf("score = %v, want %v", got, tc.want)
			}
		})
	}
}
