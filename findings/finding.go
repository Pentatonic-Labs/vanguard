// Package findings defines the Vanguard finding schema as Go types.
//
// A finding is a security weakness in your own stack that the red-team harness
// has proven (backed by a machine-checkable proof), never an unproven claim.
// The canonical schema lives in findings/schema.json.
package findings

import (
	"encoding/json"
	"fmt"
)

// Target identifies what a finding is about.
type Target struct {
	Kind    string `json:"kind"`
	Ref     string `json:"ref"`
	AssetID string `json:"asset_id,omitempty"`
}

// Vuln describes the vulnerability itself.
type Vuln struct {
	CWE          []string `json:"cwe"`
	Summary      string   `json:"summary"`
	Severity     string   `json:"severity"`
	CVSS         string   `json:"cvss,omitempty"`
	Reachability string   `json:"reachability"`
}

// Proof is the machine-checkable evidence that a finding is real.
type Proof struct {
	Repro            string   `json:"repro"`
	Artifact         string   `json:"artifact,omitempty"`
	Evidence         []string `json:"evidence,omitempty"`
	MachineCheckable bool     `json:"machine_checkable"`
}

// Fix is a proposed remediation.
type Fix struct {
	Suggestion string `json:"suggestion,omitempty"`
	PatchRef   string `json:"patch_ref,omitempty"`
	TestRef    string `json:"test_ref,omitempty"`
}

// Finding is a single proven security finding.
type Finding struct {
	SchemaVersion string   `json:"schema_version"`
	ID            string   `json:"id"`
	RunID         string   `json:"run_id"`
	Source        string   `json:"source"`
	Target        Target   `json:"target"`
	Vuln          Vuln     `json:"vuln"`
	Proof         Proof    `json:"proof"`
	Impact        string   `json:"impact"`
	Fix           *Fix     `json:"fix,omitempty"`
	References    []string `json:"references,omitempty"`
}

// Unmarshal parses a finding from its JSON representation.
func Unmarshal(data []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("unmarshal finding: %w", err)
	}
	return &f, nil
}

// Validate enforces the schema's core rule: a finding must carry a
// machine-checkable proof. Reports that fail this check are leads, not
// findings, and must not be remediated.
func Validate(f *Finding) error {
	if f == nil {
		return fmt.Errorf("finding is nil")
	}
	if f.Proof.Repro == "" {
		return fmt.Errorf("finding %q: proof.repro is required", f.ID)
	}
	if !f.Proof.MachineCheckable {
		return fmt.Errorf("finding %q: proof.machine_checkable must be true", f.ID)
	}
	return nil
}
