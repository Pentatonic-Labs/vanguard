package remediate

import (
	"strings"
	"testing"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

func TestBuild(t *testing.T) {
	decisions := []cvmcore.Decision{
		{
			Action: cvmcore.ActionPropose,
			Score:  9.8,
			Match: cvmcore.Match{
				Packages: []string{"pkg:deb/openssl@3.0.13"},
				Vuln: cvmcore.Vuln{
					ID:       "DEBIAN-CVE-2024-5535",
					Severity: "critical",
					CVSS:     9.8,
					Summary:  "Buffer overflow in OpenSSL",
					Affected: []cvmcore.VersionRange{
						{Purl: "pkg:deb/openssl", Ecosystem: "deb", Fixed: "3.0.16"},
					},
				},
			},
		},
		{
			Action: cvmcore.ActionAlert,
			Match: cvmcore.Match{
				Packages: []string{"pkg:deb/nofix@1.0"},
				Vuln: cvmcore.Vuln{
					ID:       "DEBIAN-CVE-2024-0001",
					Severity: "high",
					Affected: []cvmcore.VersionRange{{Purl: "pkg:deb/nofix", Ecosystem: "deb"}},
				},
			},
		},
	}

	proposals := Build(decisions)
	if len(proposals) != 2 {
		t.Fatalf("got %d proposals, want 2", len(proposals))
	}

	p0 := proposals[0]
	if p0.Package != "openssl" || p0.Installed != "3.0.13" || p0.Fixed != "3.0.16" {
		t.Errorf("proposal[0] = %+v, want openssl 3.0.13 -> 3.0.16", p0)
	}
	if !p0.HasFix() {
		t.Errorf("proposal[0] HasFix() = false, want true")
	}

	p1 := proposals[1]
	if p1.HasFix() {
		t.Errorf("proposal[1] HasFix() = true, want false (no fixed version known)")
	}
}

func TestSplitPurl(t *testing.T) {
	cases := []struct{ purl, name, version string }{
		{"pkg:deb/openssl@3.0.13", "openssl", "3.0.13"},
		{"pkg:deb/adb@1:34.0.4-1build3", "adb", "1:34.0.4-1build3"},
		{"pkg:deb/nover", "nover", ""},
	}
	for _, c := range cases {
		name, version := splitPurl(c.purl)
		if name != c.name || version != c.version {
			t.Errorf("splitPurl(%q) = (%q, %q), want (%q, %q)", c.purl, name, version, c.name, c.version)
		}
	}
}

func TestExplain(t *testing.T) {
	p := Proposal{
		VulnID:    "CVE-2024-5535",
		Severity:  "critical",
		CVSS:      9.8,
		Package:   "openssl",
		Installed: "3.0.13",
		Fixed:     "3.0.16",
		Action:    "propose",
		Summary:   "Buffer overflow",
	}
	s := p.Explain()
	for _, want := range []string{
		"CVE-2024-5535", "critical", "openssl", "3.0.13", "3.0.16", "propose", "Buffer overflow",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Explain missing %q in:\n%s", want, s)
		}
	}
}
