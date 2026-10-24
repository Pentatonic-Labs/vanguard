package findings

import "testing"

const sampleFinding = `{
  "schema_version": "1.0",
  "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "run_id": "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
  "source": "redteam-agent",
  "target": {"kind": "web-service", "ref": "pkg:docker/nvidia/tritonserver@sha256:abc", "asset_id": "dgx-07"},
  "vuln": {"cwe": ["CWE-89"], "summary": "SQL injection", "severity": "critical", "cvss": "9.8", "reachability": "confirmed"},
  "proof": {"repro": "curl ...", "machine_checkable": true},
  "impact": "data exfiltration",
  "fix": {"suggestion": "1.2.3 -> 1.2.4", "test_ref": "go test ./..."},
  "references": ["https://example.com"]
}`

func TestUnmarshal(t *testing.T) {
	f, err := Unmarshal([]byte(sampleFinding))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if f.ID == "" || f.Vuln.Severity != "critical" || !f.Proof.MachineCheckable {
		t.Fatalf("unexpected finding: %+v", f)
	}
	if f.Fix == nil || f.Fix.Suggestion != "1.2.3 -> 1.2.4" {
		t.Fatalf("fix not parsed: %+v", f.Fix)
	}
}

func TestUnmarshalInvalid(t *testing.T) {
	if _, err := Unmarshal([]byte("{not json")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestValidateProofGate(t *testing.T) {
	f, err := Unmarshal([]byte(sampleFinding))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(f); err != nil {
		t.Fatalf("valid finding rejected: %v", err)
	}
	f.Proof.MachineCheckable = false
	if err := Validate(f); err == nil {
		t.Fatal("expected error for non-machine-checkable finding")
	}
}
