package fixer

import (
	"strings"
	"testing"

	"github.com/Pentatonic-Labs/vanguard/findings"
)

func TestPropose(t *testing.T) {
	f := findings.Finding{
		ID:   "id-1",
		Vuln: findings.Vuln{CWE: []string{"CWE-89"}, Summary: "SQL injection", Severity: "high"},
		Fix:  &findings.Fix{Suggestion: "use parameterized queries"},
	}
	p := Propose(f, []byte("--- a/x\n+++ b/x\n"))
	if !strings.HasPrefix(p.Title, "fix:") {
		t.Fatalf("unexpected title: %q", p.Title)
	}
	if !strings.Contains(p.Body, "```diff") || !strings.Contains(p.Body, "id-1") {
		t.Fatalf("unexpected body: %s", p.Body)
	}
	if string(p.Diff) != "--- a/x\n+++ b/x\n" {
		t.Fatalf("diff not preserved: %q", p.Diff)
	}
}
