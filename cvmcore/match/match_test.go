package match

import (
	"reflect"
	"testing"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
	"github.com/Pentatonic-Labs/vanguard/inventory"
)

func pkg(name, version, purl, ecosystem string) inventory.Package {
	return inventory.Package{Name: name, Version: version, Purl: purl, Ecosystem: ecosystem}
}

func TestExactPurlMatch(t *testing.T) {
	vulns := []cvmcore.Vuln{
		{ID: "V1", PURLs: []string{"pkg:deb/openssl@1.1.1"}},
	}
	pkgs := []inventory.Package{
		pkg("openssl", "1.1.1", "pkg:deb/openssl@1.1.1", "deb"),
		pkg("libssl", "3.0.0", "pkg:deb/libssl@3.0.0", "deb"),
	}
	got := Match(vulns, pkgs, "")
	want := []string{"pkg:deb/openssl@1.1.1"}
	if len(got) != 1 || !reflect.DeepEqual(got[0].Packages, want) {
		t.Fatalf("got %+v, want packages %v", got, want)
	}
}

func TestRangeMatch(t *testing.T) {
	vulns := []cvmcore.Vuln{
		{
			ID: "V2",
			Affected: []cvmcore.VersionRange{
				{Ecosystem: "deb", Introduced: "1.0", Fixed: "2.0"},
			},
		},
	}
	pkgs := []inventory.Package{
		pkg("pkg", "1.5", "pkg:deb/pkg@1.5", "deb"), // in range
		pkg("pkg", "2.0", "pkg:deb/pkg@2.0", "deb"), // at Fixed -> out
		pkg("pkg", "0.9", "pkg:deb/pkg@0.9", "deb"), // before Introduced -> out
		pkg("pkg", "1.5", "pkg:rpm/pkg@1.5", "rpm"), // wrong ecosystem -> out
	}
	got := Match(vulns, pkgs, "")
	want := []string{"pkg:deb/pkg@1.5"}
	if len(got) != 1 || !reflect.DeepEqual(got[0].Packages, want) {
		t.Fatalf("got %+v, want packages %v", got, want)
	}
}

func TestEmptyIntroducedAndFixed(t *testing.T) {
	vulns := []cvmcore.Vuln{
		{
			ID: "lower-bound-only",
			Affected: []cvmcore.VersionRange{
				{Ecosystem: "deb", Introduced: "1.0", Fixed: ""},
			},
		},
		{
			ID: "upper-bound-only",
			Affected: []cvmcore.VersionRange{
				{Ecosystem: "deb", Introduced: "", Fixed: "2.0"},
			},
		},
	}
	pkgs := []inventory.Package{
		pkg("pkg", "0.5", "pkg:deb/pkg@0.5", "deb"),
		pkg("pkg", "1.5", "pkg:deb/pkg@1.5", "deb"),
		pkg("pkg", "3.0", "pkg:deb/pkg@3.0", "deb"),
	}
	got := Match(vulns, pkgs, "")
	if len(got) != 2 {
		t.Fatalf("want 2 matches, got %d", len(got))
	}
	// lower-bound-only: versions >= 1.0 -> 1.5 and 3.0
	if want := []string{"pkg:deb/pkg@1.5", "pkg:deb/pkg@3.0"}; !reflect.DeepEqual(got[0].Packages, want) {
		t.Errorf("lower-bound-only got %v want %v", got[0].Packages, want)
	}
	// upper-bound-only: versions < 2.0 -> 0.5 and 1.5
	if want := []string{"pkg:deb/pkg@0.5", "pkg:deb/pkg@1.5"}; !reflect.DeepEqual(got[1].Packages, want) {
		t.Errorf("upper-bound-only got %v want %v", got[1].Packages, want)
	}
}

func TestNoMatch(t *testing.T) {
	vulns := []cvmcore.Vuln{
		{ID: "V3", PURLs: []string{"pkg:deb/other@1.0"}},
		{ID: "V4"}, // no identifying info at all
	}
	pkgs := []inventory.Package{
		pkg("openssl", "1.1.1", "pkg:deb/openssl@1.1.1", "deb"),
	}
	got := Match(vulns, pkgs, "")
	if len(got) != 2 {
		t.Fatalf("want 2 matches (one per vuln), got %d", len(got))
	}
	if len(got[0].Packages) != 0 {
		t.Errorf("V3 should have no matches, got %v", got[0].Packages)
	}
	if len(got[1].Packages) != 0 {
		t.Errorf("V4 should have no matches, got %v", got[1].Packages)
	}
}

func TestCPEMatch(t *testing.T) {
	vulns := []cvmcore.Vuln{
		{
			ID:   "CVE-2022-3602",
			CPEs: []string{"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"},
		},
	}
	pkgs := []inventory.Package{
		pkg("openssl", "3.0.7", "pkg:deb/openssl@3.0.7", "deb"),
		pkg("libssl", "1.1.1", "pkg:deb/libssl@1.1.1", "deb"),
	}
	got := Match(vulns, pkgs, "")
	if len(got) != 1 {
		t.Fatalf("want 1 vuln, got %d", len(got))
	}
	// openssl 3.0.7 matches (name + 3.0 major.minor); libssl does not.
	want := []string{"pkg:deb/openssl@3.0.7"}
	if !reflect.DeepEqual(got[0].Packages, want) {
		t.Fatalf("got %v, want %v", got[0].Packages, want)
	}
}

func TestCPENoMatch(t *testing.T) {
	vulns := []cvmcore.Vuln{
		{
			ID:   "CVE-2024-1234",
			CPEs: []string{"cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*:*"},
		},
	}
	pkgs := []inventory.Package{
		pkg("openssl", "3.0.7", "pkg:deb/openssl@3.0.7", "deb"),
	}
	got := Match(vulns, pkgs, "")
	if len(got) != 1 || len(got[0].Packages) != 0 {
		t.Fatalf("want no packages matched, got %+v", got)
	}
}

func TestCPEDedupeWithPurl(t *testing.T) {
	vulns := []cvmcore.Vuln{
		{
			ID:    "CVE-2022-3602",
			PURLs: []string{"pkg:deb/openssl@3.0.7"},
			CPEs:  []string{"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"},
		},
	}
	pkgs := []inventory.Package{
		pkg("openssl", "3.0.7", "pkg:deb/openssl@3.0.7", "deb"),
	}
	got := Match(vulns, pkgs, "")
	if len(got) != 1 || len(got[0].Packages) != 1 {
		t.Fatalf("want one deduped package, got %+v", got)
	}
}

func TestDedupeAcrossPurlAndRange(t *testing.T) {
	vulns := []cvmcore.Vuln{
		{
			ID:    "V5",
			PURLs: []string{"pkg:deb/openssl@1.1.1"},
			Affected: []cvmcore.VersionRange{
				{Ecosystem: "deb", Introduced: "1.1.0", Fixed: "2.0"},
			},
		},
	}
	pkgs := []inventory.Package{
		pkg("openssl", "1.1.1", "pkg:deb/openssl@1.1.1", "deb"),
	}
	got := Match(vulns, pkgs, "")
	if len(got) != 1 || len(got[0].Packages) != 1 {
		t.Fatalf("want exactly one deduped package, got %+v", got)
	}
}

func TestReleaseScoping(t *testing.T) {
	vulns := []cvmcore.Vuln{
		{
			ID: "V6",
			Affected: []cvmcore.VersionRange{
				{Ecosystem: "deb", Release: "16.04", Fixed: "2.0"},
				{Ecosystem: "deb", Release: "24.04", Fixed: "3.0"},
			},
		},
	}
	pkgs := []inventory.Package{
		pkg("pkg", "2.5", "pkg:deb/pkg@2.5", "deb"),
	}
	if got := Match(vulns, pkgs, "24.04"); len(got[0].Packages) != 1 {
		t.Errorf("release 24.04: want 1 match (2.5 < 3.0), got %v", got[0].Packages)
	}
	if got := Match(vulns, pkgs, "16.04"); len(got[0].Packages) != 0 {
		t.Errorf("release 16.04: want 0 matches (2.5 >= 2.0), got %v", got[0].Packages)
	}
}

// A distro CVE names the SOURCE package; dpkg reports binaries. The kernel is
// the case that matters: its image comes from linux-signed-nvidia-6.17 and its
// modules from linux-nvidia-6.17, while OSV files the CVE under linux-nvidia-6.17
// only. Matching the binary name alone reported zero kernel findings on a box
// running a remotely exploitable kernel use-after-free.
func TestMatchSourcePackageIdentity(t *testing.T) {
	kernel := inventory.Package{
		Name:          "linux-image-6.17.0-1031-nvidia",
		Version:       "6.17.0-1031.31",
		Purl:          "pkg:deb/linux-image-6.17.0-1031-nvidia@6.17.0-1031.31",
		Ecosystem:     "deb",
		SourceName:    "linux-signed-nvidia-6.17",
		SourceVersion: "6.17.0-1031.31",
	}
	unrelated := pkg("bash", "5.2.15-2", "pkg:deb/bash@5.2.15-2", "deb")
	vulns := []cvmcore.Vuln{{
		ID:       "UBUNTU-CVE-2026-98432",
		Severity: "critical",
		CVSS:     9.8,
		PURLs:    []string{"pkg:deb/linux-nvidia-6.17"},
		Affected: []cvmcore.VersionRange{{
			Purl:      "pkg:deb/linux-nvidia-6.17",
			Ecosystem: "deb",
			Release:   "24.04",
			// Introduced 0 and no Fixed: the "no patch exists yet" case.
		}},
	}}

	got := Match(vulns, []inventory.Package{kernel, unrelated}, "24.04")
	if len(got) != 1 {
		t.Fatalf("got %d matches, want 1", len(got))
	}
	// The published purl must stay the BINARY, or `vanguard fix` proposes a
	// package apt cannot install.
	want := []string{"pkg:deb/linux-image-6.17.0-1031-nvidia@6.17.0-1031.31"}
	if !reflect.DeepEqual(got[0].Packages, want) {
		t.Errorf("matched packages = %v, want %v", got[0].Packages, want)
	}
}

// The source identity must not become a wildcard: a package whose source is
// pinned above the fixed version is not affected.
func TestMatchSourceIdentityRespectsFixed(t *testing.T) {
	modules := inventory.Package{
		Name:          "linux-modules-6.17.0-1032-nvidia",
		Version:       "6.17.0-1032.32",
		Purl:          "pkg:deb/linux-modules-6.17.0-1032-nvidia@6.17.0-1032.32",
		Ecosystem:     "deb",
		SourceName:    "linux-nvidia-6.17",
		SourceVersion: "6.17.0-1032.32",
	}
	vulns := []cvmcore.Vuln{{
		ID:    "UBUNTU-CVE-2099-0001",
		PURLs: []string{"pkg:deb/linux-nvidia-6.17"},
		Affected: []cvmcore.VersionRange{{
			Purl:      "pkg:deb/linux-nvidia-6.17",
			Ecosystem: "deb",
			Release:   "24.04",
			Fixed:     "6.17.0-1032.32",
		}},
	}}
	if got := Match(vulns, []inventory.Package{modules}, "24.04"); len(got[0].Packages) != 0 {
		t.Errorf("a package at the fixed version matched: %v", got[0].Packages)
	}
}
