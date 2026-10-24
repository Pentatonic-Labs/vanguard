// Package triage scores vulnerability matches and decides a remediation action.
package triage

import (
	"math"
	"sort"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// Triage scores each match and assigns a remediation action, returning the
// decisions sorted by score, highest first.
func Triage(matches []cvmcore.Match) []cvmcore.Decision {
	decisions := make([]cvmcore.Decision, 0, len(matches))
	for _, m := range matches {
		decisions = append(decisions, cvmcore.Decision{
			Match:  m,
			Action: action(m),
			Score:  score(m),
		})
	}
	sort.SliceStable(decisions, func(i, j int) bool {
		return decisions[i].Score > decisions[j].Score
	})
	return decisions
}

// score computes the triage score for a match: a base by severity, plus a KEV
// bonus, an EPSS bonus capped at 1.5, and a reachability bonus.
func score(m cvmcore.Match) float64 {
	s := severityBase(m.Vuln.Severity)
	if m.Vuln.InKEV {
		s += 1
	}
	s += math.Min(m.Vuln.EPSS*5, 1.5)
	if m.Reachable {
		s += 0.5
	}
	return s
}

// severityBase maps a severity to its base score. Unknown, empty, and
// unrecognized severities all fall back to the "unknown" score.
func severityBase(severity string) float64 {
	switch severity {
	case "critical":
		return 9
	case "high":
		return 7
	case "medium":
		return 4
	case "low":
		return 1
	default:
		return 2
	}
}

// action decides the remediation action for a match.
func action(m cvmcore.Match) cvmcore.Action {
	// No installed package, or unknown severity: alert only.
	if len(m.Packages) == 0 || m.Vuln.Severity == "" || m.Vuln.Severity == "unknown" {
		return cvmcore.ActionAlert
	}
	// Low blast radius: safe to auto-apply.
	if (m.Vuln.Severity == "low" || m.Vuln.Severity == "medium") && !m.Vuln.InKEV && m.Vuln.EPSS < 0.1 {
		return cvmcore.ActionAutoFix
	}
	return cvmcore.ActionPropose
}
