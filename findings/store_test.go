package findings

import (
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	list := []Finding{
		{
			SchemaVersion: "1.0", ID: "a", Source: "cvm",
			Target: Target{Kind: "infra", Ref: "openssl"},
			Vuln:   Vuln{Summary: "CVE-1 in openssl", Severity: "high"},
			Proof:  Proof{Repro: "x", MachineCheckable: true},
		},
		{
			SchemaVersion: "1.0", ID: "b", Source: "redteam",
			Target: Target{Kind: "web-service", Ref: "http://x"},
			Vuln:   Vuln{Summary: "IDOR", Severity: "critical"},
			Proof:  Proof{Repro: "curl x", MachineCheckable: true},
		},
	}
	if err := Save(dir, "run1", list); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("Load returned %d findings, want 2", len(got))
	}
	if got[0].ID != "a" || got[1].ID != "b" {
		t.Fatalf("Load order = %q, %q (want sorted by ID)", got[0].ID, got[1].ID)
	}
}

func TestLoadMissingDirIsEmpty(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("Load missing dir = %d findings, want 0", len(got))
	}
}

func TestParseFindingsSingleObject(t *testing.T) {
	raw := []byte(`{"schema_version":"1.0","id":"x","run_id":"r","source":"s",` +
		`"target":{"kind":"web-service","ref":"http://x"},` +
		`"vuln":{"cwe":[],"summary":"s","severity":"high"},` +
		`"proof":{"repro":"curl x","machine_checkable":true},"impact":"i"}`)
	got := parseFindings(raw)
	if len(got) != 1 || got[0].ID != "x" {
		t.Fatalf("parseFindings single object = %#v", got)
	}
}
