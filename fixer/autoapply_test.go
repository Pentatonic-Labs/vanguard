package fixer

import (
	"testing"

	"github.com/Pentatonic-Labs/vanguard/findings"
)

func TestAutoApply(t *testing.T) {
	base := findings.Finding{
		Vuln:  findings.Vuln{Severity: "low"},
		Proof: findings.Proof{MachineCheckable: true},
		Fix:   &findings.Fix{Suggestion: "1.0.0 -> 1.0.1"},
	}

	// Path 1: low severity + dependency bump -> auto-apply.
	if !AutoApply(base) {
		t.Fatal("expected auto-apply for low-severity bump")
	}

	// Path 2: high severity + bump -> no auto-apply.
	high := base
	high.Vuln.Severity = "high"
	if AutoApply(high) {
		t.Fatal("did not expect auto-apply for high severity")
	}

	// Path 3: low severity + non-bump fix -> no auto-apply.
	nonBump := base
	nonBump.Fix.Suggestion = "rewrite the whole handler"
	if AutoApply(nonBump) {
		t.Fatal("did not expect auto-apply for non-bump fix")
	}

	// Unproven finding -> no auto-apply.
	unproven := base
	unproven.Proof.MachineCheckable = false
	if AutoApply(unproven) {
		t.Fatal("did not expect auto-apply for unproven finding")
	}
}
