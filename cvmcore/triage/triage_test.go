package triage

import (
	"testing"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

func mk(severity string, epss float64, inKEV bool, packages []string) cvmcore.Match {
	return cvmcore.Match{
		Vuln: cvmcore.Vuln{
			Severity: severity,
			EPSS:     epss,
			InKEV:    inKEV,
		},
		Packages: packages,
	}
}

func TestAction(t *testing.T) {
	tests := []struct {
		name string
		m    cvmcore.Match
		want cvmcore.Action
	}{
		{"low, not kev, low epss -> auto-fix", mk("low", 0.0, false, []string{"pkg:deb/a@1"}), cvmcore.ActionAutoFix},
		{"medium, not kev, low epss -> auto-fix", mk("medium", 0.05, false, []string{"pkg:deb/a@1"}), cvmcore.ActionAutoFix},
		{"high -> propose", mk("high", 0.0, false, []string{"pkg:deb/a@1"}), cvmcore.ActionPropose},
		{"critical -> propose", mk("critical", 0.0, false, []string{"pkg:deb/a@1"}), cvmcore.ActionPropose},
		{"low but in kev -> propose", mk("low", 0.0, true, []string{"pkg:deb/a@1"}), cvmcore.ActionPropose},
		{"low but high epss -> propose", mk("low", 0.3, false, []string{"pkg:deb/a@1"}), cvmcore.ActionPropose},
		{"empty packages -> alert", mk("critical", 0.0, false, nil), cvmcore.ActionAlert},
		{"unknown severity -> alert", mk("unknown", 0.0, false, []string{"pkg:deb/a@1"}), cvmcore.ActionAlert},
		{"empty severity -> alert", mk("", 0.0, false, []string{"pkg:deb/a@1"}), cvmcore.ActionAlert},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Triage([]cvmcore.Match{tt.m})[0].Action
			if got != tt.want {
				t.Fatalf("action = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScore(t *testing.T) {
	tests := []struct {
		name string
		m    cvmcore.Match
		want float64
	}{
		{
			"critical + kev + epss1 + reachable",
			cvmcore.Match{Vuln: cvmcore.Vuln{Severity: "critical", EPSS: 1.0, InKEV: true}, Reachable: true, Packages: []string{"x"}},
			12.0,
		},
		{
			"low",
			mk("low", 0, false, []string{"x"}),
			1.0,
		},
		{
			"medium + kev + epss0.2",
			cvmcore.Match{Vuln: cvmcore.Vuln{Severity: "medium", EPSS: 0.2, InKEV: true}, Packages: []string{"x"}},
			6.0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Triage([]cvmcore.Match{tt.m})[0].Score
			if !within(got, tt.want, 1e-9) {
				t.Fatalf("score = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOrder(t *testing.T) {
	matches := []cvmcore.Match{
		mk("low", 0, false, []string{"a"}),
		mk("critical", 0, false, []string{"b"}),
		mk("high", 0, false, []string{"c"}),
		mk("medium", 0, false, []string{"d"}),
	}
	got := Triage(matches)
	want := []string{"critical", "high", "medium", "low"}
	if len(got) != len(want) {
		t.Fatalf("got %d decisions, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Match.Vuln.Severity != w {
			t.Fatalf("order[%d] severity = %q, want %q", i, got[i].Match.Vuln.Severity, w)
		}
		if i > 0 && got[i-1].Score < got[i].Score {
			t.Fatalf("not sorted descending at index %d", i)
		}
	}
}

func within(a, b, eps float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < eps
}
