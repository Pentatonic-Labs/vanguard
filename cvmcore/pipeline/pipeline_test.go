package pipeline

import (
	"context"
	"testing"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/ingest"
	"github.com/Pentatonic-Labs/vanguard/inventory"
)

const kevFixture = `{"vulnerabilities":[{"cveID":"CVE-2024-0001","vulnerabilityName":"Test KEV","shortDescription":"Actively exploited test","knownRansomwareCampaignUse":"Known"}]}`

const osvFixture = `{"results":[{"vulns":[{"id":"GHSA-0000-0000-0000","summary":"Test OSV vuln","affected":[{"package":{"ecosystem":"Debian","name":"testpkg"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]}]}],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}]}`

// noChromeFeed is an empty Chrome Releases feed.
const noChromeFeed = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"></feed>`

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
		PackagesInUse:       func() map[string]bool { return nil },
		CollectBrowsers:     func() ([]inventory.Package, error) { return nil, nil },
		FetchChromeReleases: func(ctx context.Context) ([]byte, error) { return []byte(noChromeFeed), nil },
		ParseChromeReleases: ingest.ParseChromeReleases,
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
		CollectBrowsers: func() ([]inventory.Package, error) { return nil, nil },
	}

	if _, err := Run(context.Background(), cfg); err == nil {
		t.Fatal("expected error from failed fetch, got nil")
	}
}

func TestRunReachability(t *testing.T) {
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
		PackagesInUse:       func() map[string]bool { return map[string]bool{"testpkg": true} },
		CollectBrowsers:     func() ([]inventory.Package, error) { return nil, nil },
		FetchChromeReleases: func(ctx context.Context) ([]byte, error) { return []byte(noChromeFeed), nil },
		ParseChromeReleases: ingest.ParseChromeReleases,
	}

	decisions, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, d := range decisions {
		if d.Match.Vuln.ID == "GHSA-0000-0000-0000" {
			if !d.Match.Reachable {
				t.Error("expected the matched testpkg to be Reachable")
			}
			return
		}
	}
	t.Fatal("OSV decision not found")
}

// chromeFeedFixture is a trimmed Chrome Releases Atom feed: one desktop post
// fixing CVE-2025-99999 in 141.0.7390.130, whose Linux version is 141.0.7390.122.
const chromeFeedFixture = `<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>post-1</id>
    <published>2025-10-28T18:00:00.000-07:00</published>
    <title>Stable Channel Update for Desktop</title>
    <content type="html">The Stable channel has been updated to 141.0.7390.130 for Windows and Mac and 141.0.7390.122 for Linux. High CVE-2025-99999: Type Confusion in V8. Google is aware that an exploit for CVE-2025-99999 exists in the wild.</content>
  </entry>
</feed>`

// TestRunBrowserBuildsMatchChromeReleases proves the whole browser path: a
// build collected outside the package manager is matched against the fixed
// version in the release feed, on four-part version numbers.
func TestRunBrowserBuildsMatchChromeReleases(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed string
		wantMatch bool
	}{
		{"one build behind", "141.0.7390.121", true},
		{"one stable release behind", "140.0.7339.80", true},
		{"fixed version installed", "141.0.7390.122", false},
		{"newer build", "142.0.7444.59", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				FetchKEV: func(ctx context.Context) ([]byte, error) { return []byte(`{"vulnerabilities":[]}`), nil },
				FetchNVD: func(ctx context.Context) ([]byte, error) { return []byte(`{"vulnerabilities":[]}`), nil },
				FetchOSVExport: func(ctx context.Context, ecosystem string) ([]byte, error) {
					return []byte("fake-zip"), nil
				},
				ParseOSVExport: func(data []byte) ([]cvmcore.Vuln, error) { return nil, nil },
				FetchChromeReleases: func(ctx context.Context) ([]byte, error) {
					return []byte(chromeFeedFixture), nil
				},
				// Real parser: the fixture has to survive the adapter too.
				ParseChromeReleases: ingest.ParseChromeReleases,
				CollectPackages: func() ([]inventory.Package, error) {
					return []inventory.Package{
						{Name: "testpkg", Version: "1.0", Purl: "pkg:deb/testpkg", Ecosystem: "deb"},
					}, nil
				},
				CollectBrowsers: func() ([]inventory.Package, error) {
					purl := "pkg:generic/chromium@" + tc.installed +
						"?path=/home/builder/.cache/ms-playwright/chromium-1187&unmanaged=true"
					return []inventory.Package{{
						Name:      "chromium",
						Version:   tc.installed,
						Ecosystem: inventory.ChromiumEcosystem,
						Purl:      purl,
					}}, nil
				},
				PackagesInUse: func() map[string]bool { return nil },
			}

			decisions, err := Run(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			var found *cvmcore.Decision
			for i := range decisions {
				if decisions[i].Match.Vuln.ID == "CVE-2025-99999" {
					found = &decisions[i]
					break
				}
			}
			if found == nil {
				t.Fatal("chrome releases record not in decisions")
			}
			if !found.Match.Vuln.InKEV {
				t.Error("in-the-wild post should set InKEV")
			}
			if got := len(found.Match.Packages) > 0; got != tc.wantMatch {
				t.Fatalf("matched = %v, want %v (packages %v)", got, tc.wantMatch, found.Match.Packages)
			}
		})
	}
}

// TestRunBrowserInventoryErrorIsNotFatal records that an unreadable browser
// cache is reported and skipped, not a failed scan.
func TestRunBrowserInventoryErrorIsNotFatal(t *testing.T) {
	var reported string
	cfg := Config{
		FetchKEV: func(ctx context.Context) ([]byte, error) { return []byte(`{"vulnerabilities":[]}`), nil },
		FetchNVD: func(ctx context.Context) ([]byte, error) { return []byte(`{"vulnerabilities":[]}`), nil },
		FetchOSVExport: func(ctx context.Context, ecosystem string) ([]byte, error) {
			return []byte("fake-zip"), nil
		},
		ParseOSVExport: func(data []byte) ([]cvmcore.Vuln, error) { return nil, nil },
		CollectPackages: func() ([]inventory.Package, error) {
			return []inventory.Package{{Name: "testpkg", Version: "1.0", Purl: "pkg:deb/testpkg", Ecosystem: "deb"}}, nil
		},
		CollectBrowsers: func() ([]inventory.Package, error) {
			return nil, context.DeadlineExceeded
		},
		OnFeedError:   func(feed string, err error) { reported = feed },
		PackagesInUse: func() map[string]bool { return nil },
	}
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if reported != "browser inventory" {
		t.Fatalf("reported feed = %q, want browser inventory", reported)
	}
}
