package normalize

import (
	"reflect"
	"testing"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

func TestMergeDuplicates(t *testing.T) {
	in := []cvmcore.Vuln{
		{ID: "CVE-1", PURLs: []string{"pkg:deb/a@1"}, CPEs: []string{"cpe:2.3:a:x:1"}},
		{ID: "CVE-1", PURLs: []string{"pkg:deb/b@2"}, Affected: []cvmcore.VersionRange{{Ecosystem: "deb", Fixed: "3"}}},
	}
	got := Normalize(in)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if want := []string{"pkg:deb/a@1", "pkg:deb/b@2"}; !reflect.DeepEqual(got[0].PURLs, want) {
		t.Fatalf("PURLs = %v, want %v", got[0].PURLs, want)
	}
	if want := []string{"cpe:2.3:a:x:1"}; !reflect.DeepEqual(got[0].CPEs, want) {
		t.Fatalf("CPEs = %v, want %v", got[0].CPEs, want)
	}
	if len(got[0].Affected) != 1 || got[0].Affected[0].Fixed != "3" {
		t.Fatalf("Affected = %v, want one deb range fixed at 3", got[0].Affected)
	}
}

func TestKeepsRichestRecord(t *testing.T) {
	in := []cvmcore.Vuln{
		{ID: "CVE-2", Summary: "first", InKEV: false},
		{ID: "CVE-2", Summary: "kev", InKEV: true},
		{ID: "CVE-2", Summary: "cvss", CVSS: 8.5},
	}
	got := Normalize(in)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	v := got[0]
	if v.CVSS != 8.5 {
		t.Fatalf("CVSS = %v, want 8.5 (richest record should win)", v.CVSS)
	}
	if v.Severity != "high" {
		t.Fatalf("Severity = %q, want high (filled from CVSS)", v.Severity)
	}
	if !v.InKEV {
		t.Fatalf("InKEV = false, want true (propagated)")
	}
}

func TestEPSSAndKEVPropagate(t *testing.T) {
	in := []cvmcore.Vuln{
		{ID: "CVE-3", EPSS: 0.2, InKEV: true},
		{ID: "CVE-3", EPSS: 0.9, InKEV: false},
	}
	got := Normalize(in)
	v := got[0]
	if v.EPSS != 0.9 {
		t.Fatalf("EPSS = %v, want 0.9 (max)", v.EPSS)
	}
	if !v.InKEV {
		t.Fatalf("InKEV = false, want true (OR of duplicates)")
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		cvss float64
		want string
	}{
		{9.0, "critical"},
		{8.0, "high"},
		{7.0, "high"},
		{6.0, "medium"},
		{4.0, "medium"},
		{3.0, "low"},
	}
	for _, c := range cases {
		got := Normalize([]cvmcore.Vuln{{ID: "CVE-X", CVSS: c.cvss}})
		if got[0].Severity != c.want {
			t.Errorf("CVSS %v -> Severity %q, want %q", c.cvss, got[0].Severity, c.want)
		}
	}
}

func TestSeverityLeftEmptyWithoutCVSS(t *testing.T) {
	got := Normalize([]cvmcore.Vuln{{ID: "CVE-X"}})
	if got[0].Severity != "" {
		t.Fatalf("Severity = %q, want empty (no CVSS to fill from)", got[0].Severity)
	}
}

func TestSortsByID(t *testing.T) {
	in := []cvmcore.Vuln{
		{ID: "CVE-c"},
		{ID: "CVE-a"},
		{ID: "CVE-b"},
	}
	got := Normalize(in)
	want := []string{"CVE-a", "CVE-b", "CVE-c"}
	for i, id := range want {
		if got[i].ID != id {
			t.Fatalf("got[%d].ID = %q, want %q", i, got[i].ID, id)
		}
	}
}

func TestNoOpDoesNotMutateInput(t *testing.T) {
	in := []cvmcore.Vuln{
		{ID: "CVE-b", PURLs: []string{"pkg:deb/b@1"}},
		{ID: "CVE-a", PURLs: []string{"pkg:deb/a@1"}},
	}
	before := append([]cvmcore.Vuln(nil), in...)
	got := Normalize(in)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].ID != "CVE-a" || got[1].ID != "CVE-b" {
		t.Fatalf("sort order wrong: %v", []string{got[0].ID, got[1].ID})
	}
	if !reflect.DeepEqual(in, before) {
		t.Fatalf("input mutated: %v -> %v", before, in)
	}
}
