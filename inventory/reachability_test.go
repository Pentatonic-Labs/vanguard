package inventory

import "testing"

func TestParseDpkgSOwner(t *testing.T) {
	cases := map[string]string{
		"libssl3t64:amd64: /usr/lib/x86_64-linux-gnu/libssl.so.3\n": "libssl3t64",
		"openssl: /usr/bin/openssl\n":                               "openssl",
		"no colon here":                                             "",
		"":                                                          "",
	}
	for in, want := range cases {
		if got := parseDpkgSOwner(in); got != want {
			t.Errorf("parseDpkgSOwner(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsNumeric(t *testing.T) {
	for s, want := range map[string]bool{"123": true, "1a": false, "": false, "0": true} {
		if got := isNumeric(s); got != want {
			t.Errorf("isNumeric(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestPackagesInUseRuns is a smoke test: it must not panic and must return a
// non-nil map on this (Linux) host. The exact contents are environment-
// dependent and are not asserted.
func TestPackagesInUseRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping /proc scan in -short mode")
	}
	m := PackagesInUse()
	if m == nil {
		t.Fatal("PackagesInUse returned nil")
	}
}
