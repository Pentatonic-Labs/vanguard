package fixer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pentatonic-Labs/vanguard/findings"
)

func findingWithPurl(id, purl, old, new, sev string) findings.Finding {
	return findings.Finding{
		ID:     id,
		Target: findings.Target{Ref: purl},
		Vuln:   findings.Vuln{Severity: sev, Reachability: "confirmed"},
		Proof:  findings.Proof{MachineCheckable: true, Repro: "echo"},
		Fix:    &findings.Fix{Suggestion: old + " -> " + new},
	}
}

func TestApplyGoMod(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n\n// v1.2.3 in a comment must not change\n")
	diff, err := Apply(findingWithPurl("X", "pkg:golang/github.com/foo/bar@1.2.3", "1.2.3", "1.2.4", "low"), dir)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if !strings.Contains(string(got), "github.com/foo/bar v1.2.4") {
		t.Errorf("go.mod not updated: %s", got)
	}
	if strings.Count(string(got), "v1.2.4") != 1 {
		t.Errorf("expected exactly one version edit, got:\n%s", got)
	}
	if !strings.Contains(string(got), "// v1.2.3 in a comment") {
		t.Errorf("comment was modified:\n%s", got)
	}
	if !strings.Contains(string(diff), "v1.2.4") {
		t.Errorf("diff missing new version: %s", diff)
	}
}

func TestApplyRequirements(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "requests==2.31.0\nurllib3==2.0.7\n")
	if _, err := Apply(findingWithPurl("X", "pkg:pypi/requests@2.31.0", "2.31.0", "2.32.0", "low"), dir); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "requirements.txt"))
	if !strings.Contains(string(got), "requests==2.32.0") {
		t.Errorf("requests not updated: %s", got)
	}
	if !strings.Contains(string(got), "urllib3==2.0.7") {
		t.Errorf("unrelated line changed: %s", got)
	}
}

func TestApplyPackageJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.21\",\n    \"react\": \"18.2.0\"\n  }\n}\n")
	if _, err := Apply(findingWithPurl("X", "pkg:npm/lodash@4.17.21", "4.17.21", "4.17.22", "low"), dir); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "package.json"))
	if !strings.Contains(string(got), `"lodash": "^4.17.22"`) {
		t.Errorf("lodash not updated (range prefix must be preserved): %s", got)
	}
	if !strings.Contains(string(got), `"react": "18.2.0"`) {
		t.Errorf("unrelated dependency changed: %s", got)
	}
}

func TestApplyPreciseNotFound(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example\n\ngo 1.22\n")
	if _, err := Apply(findingWithPurl("X", "pkg:golang/example.com/other@1.0.0", "1.0.0", "1.0.1", "low"), dir); err == nil {
		t.Fatal("expected error when the module is not in go.mod")
	}
}
