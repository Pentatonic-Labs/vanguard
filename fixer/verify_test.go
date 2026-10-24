package fixer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pentatonic-Labs/vanguard/findings"
)

func bumpFinding(id, old, new, sev string) findings.Finding {
	return findings.Finding{
		ID:    id,
		Vuln:  findings.Vuln{Severity: sev, Summary: "test", Reachability: "confirmed"},
		Proof: findings.Proof{MachineCheckable: true, Repro: "echo repro"},
		Fix:   &findings.Fix{Suggestion: old + " -> " + new},
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
}

func TestVerifyIsolatesAndPasses(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example\n\ngo 1.22\n")
	writeFile(t, dir, "main.go", "package main\n\nconst v = \"1.0.0\"\n")

	v := &Verifier{BuildCmd: "true", TestCmd: "true", LintCmd: "true"}
	res, err := v.Verify(bumpFinding("X-1", "1.0.0", "1.0.1", "low"), dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed() {
		t.Errorf("Passed() = false, want true; output=%q", res.Output)
	}
	if !res.Applied {
		t.Errorf("Applied = false, want true")
	}
	if !strings.Contains(res.Diff, "1.0.1") {
		t.Errorf("diff does not contain new version: %q", res.Diff)
	}
	// The original tree must be untouched.
	got, err := os.ReadFile(filepath.Join(dir, "main.go"))
	if err != nil {
		t.Fatalf("read original: %v", err)
	}
	if !strings.Contains(string(got), "1.0.0") {
		t.Errorf("original dir was modified: %q", got)
	}
}

func TestVerifyFailsGate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example\n\ngo 1.22\n")
	writeFile(t, dir, "main.go", "package main\n\nconst v = \"1.0.0\"\n")

	v := &Verifier{BuildCmd: "true", TestCmd: "false", LintCmd: "true"}
	res, err := v.Verify(bumpFinding("X-1", "1.0.0", "1.0.1", "low"), dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Passed() {
		t.Errorf("Passed() = true, want false (test gate failed)")
	}
	if res.TestsOK {
		t.Errorf("TestsOK = true, want false")
	}
}

func TestVerifyApplyFails(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example\n\ngo 1.22\n")

	v := &Verifier{BuildCmd: "true", TestCmd: "true", LintCmd: "true"}
	res, err := v.Verify(bumpFinding("X-1", "9.9.9", "9.9.10", "low"), dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Applied {
		t.Errorf("Applied = true, want false (no file contains old version)")
	}
}
