package fixer

import "github.com/Pentatonic-Labs/vanguard/findings"

// AutoApply reports whether a finding is safe to remediate without a human in
// the loop. The policy is conservative and default-deny: it returns true only
// when ALL of the following hold:
//
//   - vuln.severity is "low" or "medium"
//   - proof.machine_checkable is true
//   - fix.suggestion is a dependency-bump ("old -> new")
//
// Everything else — high/critical/info/unknown severity, unproven findings, or
// non-bump fixes — returns false.
func AutoApply(f findings.Finding) bool {
	if f.Vuln.Severity != "low" && f.Vuln.Severity != "medium" {
		return false
	}
	if !f.Proof.MachineCheckable {
		return false
	}
	if f.Fix == nil {
		return false
	}
	_, _, err := parseBump(f.Fix.Suggestion)
	return err == nil
}
