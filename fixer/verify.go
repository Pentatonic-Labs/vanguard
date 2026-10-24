package fixer

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/findings"
)

// Verification is the outcome of running a proposed fix through the dry-run
// gate on an isolated copy of the target directory.
type Verification struct {
	FindingID string `json:"finding_id"`
	Applied   bool   `json:"applied"`          // patch applied cleanly to the copy
	BuildOK   bool   `json:"build_ok"`         // build gate passed
	TestsOK   bool   `json:"tests_ok"`         // test gate passed
	LintOK    bool   `json:"lint_ok"`          // lint gate passed
	Output    string `json:"output,omitempty"` // combined gate output
	Diff      string `json:"diff,omitempty"`   // the proposed change
}

// Passed reports whether the fix applied cleanly and every configured gate
// succeeded. Only a fix whose Verification.Passed() is true may be applied.
func (v Verification) Passed() bool {
	return v.Applied && v.BuildOK && v.TestsOK && v.LintOK
}

// Verifier runs a proposed fix through the dry-run gate on an isolated copy of
// the target directory, so the live checkout is never mutated. The build, test,
// and lint commands are configurable; an empty command disables that gate.
type Verifier struct {
	BuildCmd string // "go build ./..." by default
	TestCmd  string // "go test ./..." by default
	LintCmd  string // "go vet ./..." by default
}

// NewVerifier returns a Verifier with sensible defaults.
func NewVerifier() *Verifier {
	return &Verifier{
		BuildCmd: "go build ./...",
		TestCmd:  "go test ./...",
		LintCmd:  "go vet ./...",
	}
}

// Verify copies dir to an isolated temporary directory, applies the fix there,
// runs the build/test/lint gate, and reports the result. dir is never modified
// and the temporary copy is removed.
func (v *Verifier) Verify(f findings.Finding, dir string) (Verification, error) {
	res := Verification{FindingID: f.ID}

	tmp, err := os.MkdirTemp("", "vanguard-verify-*")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)

	if err := copyTree(dir, tmp); err != nil {
		return res, fmt.Errorf("copy tree: %w", err)
	}

	diff, err := Apply(f, tmp)
	if err != nil {
		// The fix could not be applied to this target — a meaningful dry-run
		// outcome, not a fatal error.
		res.Output = err.Error()
		return res, nil
	}
	res.Applied = true
	res.Diff = string(diff)

	var out strings.Builder
	res.BuildOK = runGate(&out, tmp, v.BuildCmd, "build")
	res.TestsOK = runGate(&out, tmp, v.TestCmd, "test")
	res.LintOK = runGate(&out, tmp, v.LintCmd, "lint")
	res.Output = strings.TrimSpace(out.String())
	return res, nil
}

// runGate runs one command in dir (when non-empty) and reports pass/fail,
// appending its output to out. A disabled (empty) gate counts as passed.
func runGate(out *strings.Builder, dir, cmd, label string) bool {
	if cmd == "" {
		return true
	}
	parts := strings.Fields(cmd)
	c := exec.Command(parts[0], parts[1:]...)
	c.Dir = dir
	o, err := c.CombinedOutput()
	fmt.Fprintf(out, "[%s] %s\n%s", label, cmd, o)
	return err == nil
}

// copyTree copies src into dst recursively, skipping VCS and vendored
// directories. It builds the isolated dry-run copy.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".venv", "node_modules":
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	})
}
