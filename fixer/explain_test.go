package fixer

import (
	"strings"
	"testing"

	"github.com/Pentatonic-Labs/vanguard/findings"
)

func TestExplain(t *testing.T) {
	f := findings.Finding{
		ID:     "CVE-2024-5535",
		Vuln:   findings.Vuln{Severity: "critical", CVSS: "9.8", Summary: "Buffer overflow in OpenSSL", Reachability: "confirmed"},
		Target: findings.Target{Ref: "openssl@3.0.13"},
		Impact: "Remote code execution",
		Proof:  findings.Proof{MachineCheckable: true, Repro: "openssl version"},
		Fix:    &findings.Fix{Suggestion: "3.0.13 -> 3.0.16", TestRef: "go test ./..."},
	}
	s := Explain(f)
	for _, want := range []string{
		"CVE-2024-5535",
		"critical",
		"Buffer overflow in OpenSSL",
		"openssl@3.0.13",
		"Remote code execution",
		"3.0.13 -> 3.0.16",
		"go test ./...",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Explain missing %q in:\n%s", want, s)
		}
	}
}
