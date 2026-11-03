package remediate

import (
	"encoding/json"
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

	proposals := Build(decisions, "")
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

// One CVE, one fix, several installed binaries: a distro CVE names the source
// package, so a kernel CVE legitimately matches the image, the modules and the
// headers of every kernel line on the box. That must be one row (with the rest
// listed), not thirty — otherwise the alert is buried in its own noise.
func TestBuildCollapsesSameFix(t *testing.T) {
	decisions := []cvmcore.Decision{{
		Action: cvmcore.ActionAlert,
		Score:  9.8,
		Match: cvmcore.Match{
			Packages: []string{
				"pkg:deb/linux-image-6.17.0-1031-nvidia@6.17.0-1031.31",
				"pkg:deb/linux-modules-6.17.0-1031-nvidia@6.17.0-1031.31",
				"pkg:deb/linux-headers-6.17.0-1031-nvidia@6.17.0-1031.31",
			},
			Vuln: cvmcore.Vuln{ID: "UBUNTU-CVE-2026-98432", Severity: "critical", CVSS: 9.8,
				Affected: []cvmcore.VersionRange{{Ecosystem: "deb", Release: "24.04"}}},
		},
	}}
	got := Build(decisions, "24.04")
	if len(got) != 1 {
		t.Fatalf("got %d proposals, want 1: %+v", len(got), got)
	}
	if got[0].Package != "linux-image-6.17.0-1031-nvidia" {
		t.Errorf("kept package = %q", got[0].Package)
	}
	want := []string{"linux-headers-6.17.0-1031-nvidia", "linux-modules-6.17.0-1031-nvidia"}
	if len(got[0].AlsoAffected) != 2 || got[0].AlsoAffected[0] != want[0] || got[0].AlsoAffected[1] != want[1] {
		t.Errorf("also affected = %v, want %v", got[0].AlsoAffected, want)
	}
	if !strings.Contains(got[0].Explain(), "Also affected (2)") {
		t.Errorf("explain does not mention the collapsed packages:\n%s", got[0].Explain())
	}
}

// Collapsing must key on the fix, not just the CVE: two packages needing
// different upgrades are two actions.
func TestBuildKeepsDifferentFixes(t *testing.T) {
	decisions := []cvmcore.Decision{{
		Action: cvmcore.ActionPropose,
		Score:  7.5,
		Match: cvmcore.Match{
			Packages: []string{"pkg:deb/libssl3t64@3.0.13", "pkg:deb/openssl@3.0.13"},
			Vuln: cvmcore.Vuln{ID: "DEBIAN-CVE-2099-1", Affected: []cvmcore.VersionRange{
				{Purl: "pkg:deb/libssl3t64", Ecosystem: "deb", Release: "24.04", Fixed: "3.0.16"},
				{Purl: "pkg:deb/openssl", Ecosystem: "deb", Release: "24.04", Fixed: "3.0.17"},
			}},
		},
	}}
	if got := Build(decisions, "24.04"); len(got) != 2 {
		t.Fatalf("got %d proposals, want 2 (different fixes must not collapse)", len(got))
	}
}

// Each tier rule, one case per branch: an operator reading the short list must
// be able to trust that a finding in it is one they can act on.
func TestTierRules(t *testing.T) {
	cases := []struct {
		name      string
		severity  string
		inKEV     bool
		reachable bool
		fixed     string
		want      string
	}{
		{"kev without a fix", "medium", true, false, "", TierActNow},
		{"kev low severity", "low", true, false, "2.0", TierActNow},
		{"critical reachable with a fix", "critical", false, true, "2.0", TierActNow},
		{"high reachable with a fix", "high", false, true, "2.0", TierActNow},
		{"critical unreachable with a fix", "critical", false, false, "2.0", TierPatch},
		{"high unreachable with a fix", "high", false, false, "2.0", TierPatch},
		{"medium reachable with a fix", "medium", false, true, "2.0", TierPatch},
		{"medium unreachable with a fix", "medium", false, false, "2.0", TierNoise},
		{"low reachable with a fix", "low", false, true, "2.0", TierNoise},
		{"critical without a fix", "critical", false, true, "", TierWatch},
		{"high without a fix", "high", false, false, "", TierWatch},
		{"medium without a fix", "medium", false, true, "", TierNoise},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := cvmcore.Vuln{ID: "DEBIAN-CVE-2099-1", Severity: c.severity, InKEV: c.inKEV}
			if c.fixed != "" {
				v.Affected = []cvmcore.VersionRange{{Purl: "pkg:deb/widget", Fixed: c.fixed}}
			}
			got := BuildWithKernel([]cvmcore.Decision{{
				Action: cvmcore.ActionPropose,
				Score:  5,
				Match:  cvmcore.Match{Packages: []string{"pkg:deb/widget@1.0"}, Vuln: v, Reachable: c.reachable},
			}}, "", "6.17.0-1031-nvidia")
			if len(got) != 1 {
				t.Fatalf("got %d proposals, want 1", len(got))
			}
			if got[0].Tier != c.want {
				t.Errorf("tier = %q, want %q for %+v", got[0].Tier, c.want, got[0])
			}
		})
	}
}

// Package names a kernel fix actually ships as, against running
// 6.17.0-1031-nvidia. The release has to be found anywhere in the name, and a
// name with no release at all is how fixes arrive — never stale.
func TestKernelRelation(t *testing.T) {
	const running = "6.17.0-1031-nvidia"
	cases := []struct {
		pkg  string
		want kernelRelation
	}{
		// Metapackages: no embedded release, and they are how kernel fixes arrive.
		{"linux-image-nvidia-hwe-24.04", kernelUnknown},
		{"linux-headers-generic", kernelUnknown},
		{"linux-modules-nvidia-fs-nvidia-hwe-24.04", kernelUnknown},
		// Family words before the release, on the running kernel.
		{"linux-modules-nvidia-580-open-6.17.0-1031-nvidia", kernelCurrent},
		{"linux-modules-nvidia-fs-6.17.0-1031-nvidia", kernelCurrent},
		{"linux-image-6.17.0-1031-nvidia", kernelCurrent},
		{"linux-headers-6.17.0-1031-nvidia", kernelCurrent},
		// Unflavoured headers of the running ABI.
		{"linux-headers-6.17.0-1031", kernelCurrent},
		{"linux-tools-6.17.0-1031", kernelCurrent},
		// Older kernel lines.
		{"linux-image-6.17.0-1029-nvidia", kernelOlder},
		{"linux-headers-6.11.0-1014-nvidia", kernelOlder},
		{"linux-nvidia-6.11-headers-6.11.0-1014", kernelOlder},
		// Newer and waiting for a reboot.
		{"linux-image-7.0.0-1019-nvidia", kernelNewer},
		{"linux-modules-nvidia-580-open-6.17.0-1032-nvidia", kernelNewer},
		// Not kernel packages, whatever digits they carry.
		{"linux-firmware", kernelUnknown},
		{"linux-libc-dev", kernelUnknown},
		{"openssl", kernelUnknown},
	}
	for _, c := range cases {
		if got := classifyKernel(c.pkg, running); got != c.want {
			t.Errorf("classifyKernel(%q, %q) = %v, want %v", c.pkg, running, got, c.want)
		}
	}
	// An unflavoured running kernel (linux-headers-6.17.0-1031 style) works too.
	if got := classifyKernel("linux-image-6.17.0-1031-nvidia", "6.17.0-1031"); got != kernelCurrent {
		t.Errorf("unflavoured running kernel: got %v, want current", got)
	}
	// With no running kernel known nothing may be called stale or pending:
	// wrongly hiding a finding is worse than listing a kernel package.
	for _, pkg := range []string{"linux-image-6.17.0-1029-nvidia", "linux-image-7.0.0-1019-nvidia"} {
		if got := classifyKernel(pkg, ""); got != kernelUnknown {
			t.Errorf("classifyKernel(%q, no running kernel) = %v, want unknown", pkg, got)
		}
	}
}

// Numeric, not lexical: 6.17.0-999 is older than 6.17.0-1031.
func TestCompareKernelBase(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.17.0-1031", "6.17.0-1031", 0},
		{"6.17.0-999", "6.17.0-1031", -1},
		{"6.11.0-1014", "6.17.0-1031", -1},
		{"7.0.0-1019", "6.17.0-1031", 1},
		{"6.17.1-1014", "6.17.0-1031", 1},
		{"6.17.0-1032", "6.17.0-1031", 1},
	}
	for _, c := range cases {
		if got := compareKernelBase(c.a, c.b); got != c.want {
			t.Errorf("compareKernelBase(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestStaleKernelProposalIsNoise(t *testing.T) {
	decisions := []cvmcore.Decision{{
		Action: cvmcore.ActionPropose,
		Score:  9.8,
		Match: cvmcore.Match{
			Packages:  []string{"pkg:deb/linux-headers-6.17.0-1029-nvidia@6.17.0-1029.29"},
			Reachable: true,
			Vuln: cvmcore.Vuln{ID: "UBUNTU-CVE-2026-98432", Severity: "critical", CVSS: 9.8,
				Affected: []cvmcore.VersionRange{{Ecosystem: "deb", Release: "24.04", Fixed: "6.17.0-1031.31"}}},
		},
	}}
	got := BuildWithKernel(decisions, "24.04", "6.17.0-1031-nvidia")
	if len(got) != 1 {
		t.Fatalf("got %d proposals, want 1", len(got))
	}
	if !got[0].StaleKernel || got[0].Tier != TierNoise {
		t.Errorf("stale kernel proposal = %+v, want stale noise (critical+reachable+fixed would be act-now)", got[0])
	}
}

// A row that covers the running kernel as well as an older one is a real
// finding: only rows where every package is stale may be demoted.
func TestStaleKernelRowWithRunningKernelIsNotStale(t *testing.T) {
	decisions := []cvmcore.Decision{{
		Action: cvmcore.ActionPropose,
		Score:  9.8,
		Match: cvmcore.Match{
			Packages: []string{
				"pkg:deb/linux-image-6.17.0-1031-nvidia@6.17.0-1031.31",
				"pkg:deb/linux-image-6.17.0-1029-nvidia@6.17.0-1029.29",
			},
			Vuln: cvmcore.Vuln{ID: "UBUNTU-CVE-2026-98433", Severity: "critical", CVSS: 9.8,
				Affected: []cvmcore.VersionRange{{Ecosystem: "deb", Release: "24.04", Fixed: "6.17.0-1032.32"}}},
		},
	}}
	got := BuildWithKernel(decisions, "24.04", "6.17.0-1031-nvidia")
	if len(got) != 1 {
		t.Fatalf("got %d proposals, want 1 collapsed row", len(got))
	}
	if got[0].StaleKernel {
		t.Errorf("row covering the running kernel marked stale, tier %q", got[0].Tier)
	}
	if got[0].Tier == TierNoise {
		t.Errorf("row covering the running kernel demoted to noise")
	}
}

// A newer kernel is installed, not stale: there is nothing to remove, and the
// CVE it carries is real until the reboot, so it keeps its tier.
func TestNewerKernelIsPendingRebootNotStale(t *testing.T) {
	decisions := []cvmcore.Decision{{
		Action: cvmcore.ActionPropose,
		Score:  9.8,
		Match: cvmcore.Match{
			Packages:  []string{"pkg:deb/linux-image-7.0.0-1019-nvidia@7.0.0-1019.31"},
			Reachable: true,
			Vuln: cvmcore.Vuln{ID: "UBUNTU-CVE-2026-98434", Severity: "critical", CVSS: 9.8,
				Affected: []cvmcore.VersionRange{{Ecosystem: "deb", Release: "24.04", Fixed: "7.0.0-1020.32"}}},
		},
	}}
	got := BuildWithKernel(decisions, "24.04", "6.17.0-1031-nvidia")
	if len(got) != 1 {
		t.Fatalf("got %d proposals, want 1", len(got))
	}
	if got[0].StaleKernel {
		t.Errorf("newer kernel marked stale (would be reported for removal): %+v", got[0])
	}
	if !got[0].PendingReboot {
		t.Errorf("newer kernel not marked pending reboot: %+v", got[0])
	}
	if got[0].Tier != TierActNow {
		t.Errorf("tier = %q, want %q: newer is not stale, and the CVE is real until the reboot",
			got[0].Tier, TierActNow)
	}
	if !strings.Contains(got[0].Explain(), "reboot to apply") {
		t.Errorf("explain does not mention the reboot:\n%s", got[0].Explain())
	}
}

// A metapackage carries no release and is never stale: it is how the fixed
// kernel arrives, so demoting it would hide the upgrade.
func TestKernelMetapackageIsNotStale(t *testing.T) {
	decisions := []cvmcore.Decision{{
		Action: cvmcore.ActionPropose,
		Score:  9.8,
		Match: cvmcore.Match{
			Packages:  []string{"pkg:deb/linux-image-nvidia-hwe-24.04@6.11.0-1014.14"},
			Reachable: true,
			Vuln: cvmcore.Vuln{ID: "UBUNTU-CVE-2026-98435", Severity: "critical", CVSS: 9.8,
				Affected: []cvmcore.VersionRange{{Ecosystem: "deb", Release: "24.04", Fixed: "6.17.0-1031.31"}}},
		},
	}}
	got := BuildWithKernel(decisions, "24.04", "6.17.0-1031-nvidia")
	if len(got) != 1 {
		t.Fatalf("got %d proposals, want 1", len(got))
	}
	if got[0].StaleKernel || got[0].PendingReboot {
		t.Errorf("metapackage classified as a kernel package: %+v", got[0])
	}
	if got[0].Tier != TierActNow {
		t.Errorf("tier = %q, want %q", got[0].Tier, TierActNow)
	}
}

// The scan's --json output and the findings it persists are consumed by other
// tools, so the triage fields need stable names.
func TestProposalJSONIncludesTriageFields(t *testing.T) {
	b, err := json.Marshal(Proposal{VulnID: "CVE-2099-1", Tier: TierActNow, StaleKernel: true, PendingReboot: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"tier":"act-now"`, `"stale_kernel":true`, `"pending_reboot":true`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("proposal JSON missing %s: %s", want, b)
		}
	}
}
