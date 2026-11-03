package main

import (
	"strings"
	"testing"

	"github.com/Pentatonic-Labs/vanguard/cvmcore/remediate"
)

// one proposal per tier.
func tierFixture() []remediate.Proposal {
	return []remediate.Proposal{
		{VulnID: "CVE-2099-1", Severity: "critical", Package: "openssl", Installed: "3.0.13",
			Fixed: "3.0.16", Action: "propose", Tier: remediate.TierActNow},
		{VulnID: "CVE-2099-2", Severity: "high", Package: "curl", Installed: "8.0",
			Fixed: "8.1", Action: "propose", Tier: remediate.TierPatch},
		{VulnID: "CVE-2099-3", Severity: "critical", Package: "zlib", Installed: "1.2",
			Action: "alert", Tier: remediate.TierWatch},
		{VulnID: "CVE-2099-4", Severity: "low", Package: "nano", Installed: "7.2",
			Fixed: "7.3", Action: "propose", Tier: remediate.TierNoise},
	}
}

// A critical CVE on the previous kernel line: one collapsed row covering that
// kernel's binaries, of which there are thousands of findings' worth.
func staleFixture() []remediate.Proposal {
	return []remediate.Proposal{{
		VulnID:      "CVE-2099-9",
		Severity:    "critical",
		Package:     "linux-image-6.17.0-1029-nvidia",
		Installed:   "6.17.0-1029.29",
		Fixed:       "6.17.0-1031.31",
		Action:      "propose",
		Tier:        remediate.TierNoise,
		StaleKernel: true,
		AlsoAffected: []string{
			"linux-headers-6.17.0-1029-nvidia",
			"linux-modules-6.17.0-1029-nvidia",
		},
	}}
}

// A kernel newer than the running one is installed and waiting for a reboot: it
// must never be reported as removable, and it keeps its tier because the CVE is
// real until the reboot.
func pendingRebootFixture() []remediate.Proposal {
	return []remediate.Proposal{{
		VulnID:        "CVE-2099-8",
		Severity:      "critical",
		Package:       "linux-image-7.0.0-1019-nvidia",
		Installed:     "7.0.0-1019.31",
		Fixed:         "7.0.0-1020.32",
		Action:        "propose",
		Tier:          remediate.TierActNow,
		PendingReboot: true,
		AlsoAffected:  []string{"linux-modules-nvidia-580-open-7.0.0-1019-nvidia"},
	}}
}

func TestScanOutputListsOnlyActionableTiers(t *testing.T) {
	out := scanOutput(tierFixture(), false)
	if !strings.Contains(out, "tiers: act-now 1, patch 1, watch 1, noise 1") {
		t.Errorf("missing tier summary:\n%s", out)
	}
	for _, want := range []string{"CVE-2099-1", "CVE-2099-2"} {
		if !strings.Contains(out, want) {
			t.Errorf("act-now/patch finding %q not listed:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"CVE-2099-3", "CVE-2099-4"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("watch/noise finding %q listed by default:\n%s", unwanted, out)
		}
	}
}

func TestScanOutputAllListsEveryTier(t *testing.T) {
	out := scanOutput(tierFixture(), true)
	for _, want := range []string{"CVE-2099-1", "CVE-2099-2", "CVE-2099-3", "CVE-2099-4"} {
		if !strings.Contains(out, want) {
			t.Errorf("--all output missing %q:\n%s", want, out)
		}
	}
}

// The stale kernel is one line, not thousands of findings.
func TestScanOutputCollapsesStaleKernelToOneLine(t *testing.T) {
	out := scanOutput(append(tierFixture(), staleFixture()...), false)
	if n := strings.Count(out, "old kernel packages"); n != 1 {
		t.Fatalf("stale kernel mentioned on %d lines, want 1:\n%s", n, out)
	}
	var line string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "old kernel packages") {
			line = l
		}
	}
	for _, want := range []string{
		"linux-image-6.17.0-1029-nvidia",
		"linux-headers-6.17.0-1029-nvidia",
		"linux-modules-6.17.0-1029-nvidia",
		"older than the running kernel",
		"remove",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("stale kernel line missing %q: %s", want, line)
		}
	}
	// The finding itself is noise: not listed among the actionable ones.
	if strings.Contains(out, "CVE-2099-9") {
		t.Errorf("stale kernel finding listed by default:\n%s", out)
	}
}

func TestScanOutputNothingToActOn(t *testing.T) {
	out := scanOutput(staleFixture(), false)
	if !strings.Contains(out, "nothing to act on now") {
		t.Errorf("no actionable findings should say so:\n%s", out)
	}
	if !strings.Contains(out, "tiers: act-now 0, patch 0, watch 0, noise 1") {
		t.Errorf("missing tier summary:\n%s", out)
	}
}

// The newer kernel gets its own line, says reboot, and says nothing about
// removing it.
func TestScanOutputSeparatesPendingRebootFromOldKernels(t *testing.T) {
	out := scanOutput(append(append(tierFixture(), staleFixture()...), pendingRebootFixture()...), false)

	var oldLine, newLine string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "old kernel packages") {
			oldLine = l
		}
		if strings.Contains(l, "reboot pending") {
			newLine = l
		}
	}
	if newLine == "" {
		t.Fatalf("no reboot-pending line:\n%s", out)
	}
	if !strings.Contains(newLine, "7.0.0-1019-nvidia") {
		t.Errorf("reboot-pending line does not name the release: %s", newLine)
	}
	for _, unwanted := range []string{"remove", "old kernel"} {
		if strings.Contains(newLine, unwanted) {
			t.Errorf("reboot-pending line must not suggest removal (%q): %s", unwanted, newLine)
		}
	}
	if strings.Contains(oldLine, "7.0.0-1019-nvidia") {
		t.Errorf("newer kernel listed as removable: %s", oldLine)
	}
	// The newer kernel is still a real finding until the reboot, so it is listed.
	if !strings.Contains(out, "CVE-2099-8") {
		t.Errorf("pending-reboot finding not listed in the actionable tiers:\n%s", out)
	}
}
