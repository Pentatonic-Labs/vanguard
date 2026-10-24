package fixer

import (
	"fmt"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/findings"
)

// Explain returns a plain-English description of a finding and its proposed
// fix, for review by a person who should not have to read code or diffs:
// what the problem is, what it affects, why it matters, the proposed fix, and
// how it is verified.
func Explain(f findings.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s — severity %s", f.ID, f.Vuln.Severity)
	if f.Vuln.CVSS != "" {
		fmt.Fprintf(&b, " (CVSS %s)", f.Vuln.CVSS)
	}
	if f.Vuln.Summary != "" {
		fmt.Fprintf(&b, "\n  Problem: %s", f.Vuln.Summary)
	}
	if f.Target.Ref != "" {
		fmt.Fprintf(&b, "\n  Affects: %s", f.Target.Ref)
	}
	if f.Impact != "" {
		fmt.Fprintf(&b, "\n  Why it matters: %s", f.Impact)
	}
	if f.Fix != nil && f.Fix.Suggestion != "" {
		fmt.Fprintf(&b, "\n  Proposed fix: %s", f.Fix.Suggestion)
	}
	if f.Fix != nil && f.Fix.TestRef != "" {
		fmt.Fprintf(&b, "\n  Verified by: %s", f.Fix.TestRef)
	}
	switch {
	case f.Proof.MachineCheckable && f.Proof.Repro != "":
		fmt.Fprintf(&b, "\n  Proof: %s", truncate(f.Proof.Repro, 200))
	case !f.Proof.MachineCheckable:
		b.WriteString("\n  Proof: NONE — unproven (treat as a lead, not a finding)")
	}
	return b.String()
}

// truncate shortens s to at most n bytes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
