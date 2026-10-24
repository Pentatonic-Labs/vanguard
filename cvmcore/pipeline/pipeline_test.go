package pipeline

import (
	"context"
	"testing"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
	"github.com/Pentatonic-Labs/vanguard/inventory"
)

const kevFixture = `{"vulnerabilities":[{"cveID":"CVE-2024-0001","vulnerabilityName":"Test KEV","shortDescription":"Actively exploited test","knownRansomwareCampaignUse":"Known"}]}`

const osvFixture = `{"results":[{"vulns":[{"id":"GHSA-0000-0000-0000","summary":"Test OSV vuln","affected":[{"package":{"ecosystem":"Debian","name":"testpkg"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]}]}],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}]}`

const nvdFixture = `{"vulnerabilities":[{"cve":{"id":"CVE-2024-0002","descriptions":[{"lang":"en","value":"Test NVD vuln"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM"}}]},"configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*","vulnerable":true}]}]}]}}]}`

func TestRunEndToEnd(t *testing.T) {
	cfg := Config{
		FetchKEV: func(ctx context.Context) ([]byte, error) { return []byte(kevFixture), nil },
		FetchNVD: func(ctx context.Context) ([]byte, error) { return []byte(nvdFixture), nil },
		FetchOSVExport: func(ctx context.Context, ecosystem string) ([]byte, error) {
			return []byte("fake-zip"), nil
		},
		ParseOSVExport: func(data []byte) ([]cvmcore.Vuln, error) {
			return []cvmcore.Vuln{{
				ID:       "GHSA-0000-0000-0000",
				Source:   "osv",
				Severity: "critical",
				CVSS:     9.8,
				PURLs:    []string{"pkg:deb/testpkg"},
				Affected: []cvmcore.VersionRange{{Ecosystem: "deb", Fixed: "2.0"}},
			}}, nil
		},
		CollectPackages: func() ([]inventory.Package, error) {
			return []inventory.Package{
				{Name: "testpkg", Version: "1.0", Purl: "pkg:deb/testpkg", Ecosystem: "deb"},
			}, nil
		},
	}

	decisions, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(decisions) != 3 {
		t.Fatalf("want 3 decisions, got %d", len(decisions))
	}

	// Highest score first: the critical OSV vuln that matched an installed
	// package should lead with a propose action and the matching purl.
	first := decisions[0]
	if first.Action != cvmcore.ActionPropose {
		t.Errorf("first action = %q, want %q", first.Action, cvmcore.ActionPropose)
	}
	if len(first.Match.Packages) != 1 || first.Match.Packages[0] != "pkg:deb/testpkg" {
		t.Errorf("first packages = %v, want [pkg:deb/testpkg]", first.Match.Packages)
	}
	if first.Match.Vuln.ID != "GHSA-0000-0000-0000" {
		t.Errorf("first vuln ID = %q, want GHSA-0000-0000-0000", first.Match.Vuln.ID)
	}
}

func TestRunFetchError(t *testing.T) {
	cfg := Config{
		FetchKEV: func(ctx context.Context) ([]byte, error) {
			return nil, context.DeadlineExceeded
		},
		CollectPackages: func() ([]inventory.Package, error) {
			return nil, nil
		},
	}

	if _, err := Run(context.Background(), cfg); err == nil {
		t.Fatal("expected error from failed fetch, got nil")
	}
}
