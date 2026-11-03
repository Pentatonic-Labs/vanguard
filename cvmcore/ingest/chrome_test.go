package ingest

import (
	"os"
	"testing"
)

const chromeFeedFixture = "testdata/chrome-releases-atom.xml"

func TestParseChromeReleasesFixture(t *testing.T) {
	data, err := os.ReadFile(chromeFeedFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	vulns, err := ParseChromeReleases(data)
	if err != nil {
		t.Fatalf("ParseChromeReleases: %v", err)
	}

	// The Android post is in the feed but not a desktop release, so only the
	// two desktop CVEs may come out.
	if len(vulns) != 2 {
		t.Fatalf("got %d vulns, want 2: %+v", len(vulns), vulns)
	}

	byID := make(map[string]int, len(vulns))
	for i, v := range vulns {
		byID[v.ID] = i
	}
	if _, ok := byID["CVE-2025-33333"]; ok {
		t.Errorf("Android post produced a record: %+v", vulns[byID["CVE-2025-33333"]])
	}

	wild, ok := byID["CVE-2025-11111"]
	if !ok {
		t.Fatalf("missing CVE-2025-11111 in %+v", vulns)
	}
	if !vulns[wild].InKEV || vulns[wild].ExploitStatus != "active" {
		t.Errorf("in-the-wild CVE not marked exploited: %+v", vulns[wild])
	}
	if vulns[wild].Severity != "high" {
		t.Errorf("severity = %q, want high", vulns[wild].Severity)
	}

	quiet, ok := byID["CVE-2025-22222"]
	if !ok {
		t.Fatalf("missing CVE-2025-22222 in %+v", vulns)
	}
	if vulns[quiet].InKEV || vulns[quiet].ExploitStatus == "active" {
		t.Errorf("CVE not named as exploited was marked exploited: %+v", vulns[quiet])
	}
	if vulns[quiet].Severity != "medium" {
		t.Errorf("severity = %q, want medium", vulns[quiet].Severity)
	}

	// The Linux fixed version, not the Windows/Mac one in the same sentence.
	for _, v := range vulns {
		if len(v.Affected) != 1 {
			t.Fatalf("%s: got %d ranges, want 1", v.ID, len(v.Affected))
		}
		r := v.Affected[0]
		if r.Fixed != "141.0.7390.122" {
			t.Errorf("%s: fixed = %q, want 141.0.7390.122", v.ID, r.Fixed)
		}
		if r.Ecosystem != ChromeEcosystem {
			t.Errorf("%s: ecosystem = %q, want %q", v.ID, r.Ecosystem, ChromeEcosystem)
		}
		if len(v.PURLs) != 1 || v.PURLs[0] != chromePURL {
			t.Errorf("%s: purls = %v, want [%s]", v.ID, v.PURLs, chromePURL)
		}
	}
}

func TestParseChromeReleasesInvalidXML(t *testing.T) {
	if _, err := ParseChromeReleases([]byte("not a feed")); err == nil {
		t.Fatal("expected error for invalid feed, got nil")
	}
}

func TestParseChromeReleasesSkipsPostWithoutLinuxVersion(t *testing.T) {
	feed := `<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Stable Channel Update for Desktop</title>
    <published>2025-11-01T00:00:00Z</published>
    <content type="html">This update includes 1 security fix. High CVE-2025-44444: Use after free in Blink.</content>
  </entry>
</feed>`
	vulns, err := ParseChromeReleases([]byte(feed))
	if err != nil {
		t.Fatalf("ParseChromeReleases: %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("got %d vulns without a fixed version, want 0: %+v", len(vulns), vulns)
	}
}

func TestLinuxVersionWording(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "linux after version",
			body: "The Stable channel has been updated to 142.0.7444.60 for Windows, Mac and Linux.",
			want: "142.0.7444.60",
		},
		{
			name: "per platform versions",
			body: "updated to 142.0.7444.60 for Windows and Mac and 142.0.7444.59 for Linux.",
			want: "142.0.7444.59",
		},
		{
			name: "linux label first",
			body: "Linux: 142.0.7444.59\nWindows: 142.0.7444.60",
			want: "142.0.7444.59",
		},
		{
			name: "no linux mention",
			body: "updated to 142.0.7444.60 for all platforms.",
			want: "142.0.7444.60",
		},
		{
			name: "no version at all",
			body: "This update includes 1 security fix.",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linuxVersion(tt.body); got != tt.want {
				t.Fatalf("linuxVersion = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWildCVENaming(t *testing.T) {
	ids, all := wildCVEs("Google is aware that an exploit for CVE-2025-11111 exists in the wild.")
	if all {
		t.Error("named CVE should not set the all-CVEs flag")
	}
	if !ids["CVE-2025-11111"] {
		t.Errorf("ids = %v, want CVE-2025-11111", ids)
	}

	ids, all = wildCVEs("Google is aware that an exploit exists in the wild.")
	if !all || len(ids) != 0 {
		t.Errorf("unnamed in-the-wild line = (%v, %v), want all", ids, all)
	}

	if _, all := wildCVEs("This update includes 2 security fixes."); all {
		t.Error("a post with no in-the-wild line set the flag")
	}
}
