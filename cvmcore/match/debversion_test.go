package match

import (
	"os/exec"
	"testing"
)

// canonicalCases are Debian version pairs with their expected ordering. They
// are also cross-checked against dpkg --compare-versions below.
var canonicalCases = []struct {
	a, b string
	want int
}{
	{"1.0", "1.0", 0},
	{"1.0", "1.0-1", -1},   // a revision makes a version newer
	{"1.0-1", "1.0-2", -1}, // later revision is newer
	{"1.0~rc1", "1.0", -1}, // tilde is a pre-release
	{"1.0~~", "1.0~", -1},  // more tildes sort earlier
	{"1.0", "1.0a", -1},    // a letter sorts after the empty string
	{"1.0a", "1.0b", -1},   // letters compare lexically
	{"2.0", "10", -1},      // digit runs compare numerically, not lexically
	{"1.0", "1:1.0", -1},   // epoch dominates
	{"1:1.0", "2.0", 1},    // a higher epoch beats a higher version
	{"1.0-1", "1.0-1build3", -1},
	{"1.0-1ubuntu1", "1.0-1", 1},
	{"1.0-0", "1.0", 0}, // revision "0" equals no revision
	{"0.9.6-1", "0.9.6-1.1", -1},
	{"1.0", "1.00", 0}, // leading zeros are ignored
	{"1:34.0.4-1build3", "1:34.0.4-1build4", -1},
	{"1:34.0.4-1build3", "0.9.6-1", 1},
}

func TestCompareDebianVersionCanonical(t *testing.T) {
	for _, c := range canonicalCases {
		if got := compareDebianVersion(c.a, c.b); got != c.want {
			t.Errorf("compareDebianVersion(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := compareDebianVersion(c.b, c.a); got != -c.want {
			t.Errorf("compareDebianVersion(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

// dpkgVersions is a diverse corpus of real and synthetic Debian versions used
// for the dpkg cross-validation.
var dpkgVersions = []string{
	"1.0", "1.0-1", "1.0-0", "1.0~rc1", "1.0~~", "1.0~", "1.0a", "1.0b",
	"2.0", "10", "1:1.0", "1:34.0.4-1build3", "1:34.0.4-1build4",
	"0.9.6-1", "0.9.6-1.1", "1.0-1ubuntu1", "1.0-1build3",
	"4.0.1really4.0.1-0ubuntu0.24.04.5", "1:2.11-8", "1:9.18.39-0ubuntu0.24.04.8",
	"2:2.7.0-1ubuntu4.2", "1:2.39.3-9ubuntu6.6", "0.49~24.04.1",
	"1.6.13-3ubuntu0.2", "2.76+ubuntu24.04.1", "1:5.45-3build1",
	"1:2.43.0-1ubuntu7.4", "3.0.13-0ubuntu3.16", "2:1.21-75+exp1",
	"1:15.1.01-1build1", "1:1.36.1-6ubuntu3.1", "0.8-13ubuntu6.2",
}

// TestCompareDebianVersionAgainstDpkg cross-validates the implementation
// against the system dpkg --compare-versions, which is the authoritative
// Debian version-ordering implementation.
func TestCompareDebianVersionAgainstDpkg(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping dpkg cross-validation in -short mode")
	}
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg not available")
	}

	for _, a := range dpkgVersions {
		for _, b := range dpkgVersions {
			want := dpkgCompare(t, a, b)
			if got := compareDebianVersion(a, b); got != want {
				t.Errorf("compareDebianVersion(%q, %q) = %d, dpkg says %d", a, b, got, want)
			}
		}
	}
}

// dpkgCompare returns the sign of (a vs b) according to dpkg --compare-versions.
func dpkgCompare(t *testing.T, a, b string) int {
	t.Helper()
	run := func(op string) (bool, error) {
		err := exec.Command("dpkg", "--compare-versions", a, op, b).Run()
		if err == nil {
			return true, nil
		}
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return false, nil // comparison is false
		}
		return false, err // dpkg error (exit code 2)
	}
	if lt, err := run("lt"); err == nil && lt {
		return -1
	}
	if gt, err := run("gt"); err == nil && gt {
		return 1
	}
	if eq, err := run("eq"); err == nil && eq {
		return 0
	}
	t.Fatalf("dpkg --compare-versions failed for %q vs %q", a, b)
	return 0
}
