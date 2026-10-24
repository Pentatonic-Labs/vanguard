package fixer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pentatonic-Labs/vanguard/findings"
)

func findingWithFix(suggestion string) findings.Finding {
	return findings.Finding{
		ID:    "id-1",
		Vuln:  findings.Vuln{Severity: "medium"},
		Proof: findings.Proof{MachineCheckable: true},
		Fix:   &findings.Fix{Suggestion: suggestion},
	}
}

func TestParseBump(t *testing.T) {
	old, new, err := parseBump("1.2.3 -> 1.2.4")
	if err != nil || old != "1.2.3" || new != "1.2.4" {
		t.Fatalf("parseBump = %q, %q, %v", old, new, err)
	}
	if _, _, err := parseBump("no arrow here"); err == nil {
		t.Fatal("expected error for non-bump suggestion")
	}
	if _, _, err := parseBump("1.0.0 -> 1.0.0"); err == nil {
		t.Fatal("expected error when old == new")
	}
}

func TestApply(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "go.mod")
	content := "module example\n\ngo 1.22\n\nrequire example.com/lib v1.2.3\n"
	if err := os.WriteFile(manifest, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	diff, err := Apply(findingWithFix("v1.2.3 -> v1.2.4"), dir)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "v1.2.4") || strings.Contains(string(got), "v1.2.3") {
		t.Fatalf("manifest not updated:\n%s", got)
	}
	if !strings.Contains(string(diff), "--- a/go.mod") {
		t.Fatalf("diff missing file header:\n%s", diff)
	}
	if !strings.Contains(string(diff), "-require example.com/lib v1.2.3") ||
		!strings.Contains(string(diff), "+require example.com/lib v1.2.4") {
		t.Fatalf("diff missing change lines:\n%s", diff)
	}
}

func TestApplyNoMatch(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.txt"), []byte("no versions here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(findingWithFix("1.0.0 -> 1.0.1"), dir); err == nil {
		t.Fatal("expected error when no files match")
	}
}
