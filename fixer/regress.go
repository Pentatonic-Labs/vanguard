package fixer

import (
	"os/exec"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/findings"
)

// defaultTestCommand is used when a finding does not carry a test_ref.
const defaultTestCommand = "go test ./..."

// RegressResult reports the outcome of a regression test run.
type RegressResult struct {
	Passed bool
	Output string
}

// runCmd executes cmd in dir and returns its combined output. It is a variable
// so tests can substitute a deterministic fake.
var runCmd = func(dir, cmd string) (string, error) {
	parts := strings.Fields(cmd)
	c := exec.Command(parts[0], parts[1:]...)
	c.Dir = dir
	out, err := c.CombinedOutput()
	return string(out), err
}

// Regress runs the regression test for f in dir and reports pass/fail. The
// command defaults to "go test ./..." unless the finding carries a test_ref.
// A non-nil error accompanies a Passed=false result.
func Regress(f findings.Finding, dir string) (RegressResult, error) {
	cmd := defaultTestCommand
	if f.Fix != nil && f.Fix.TestRef != "" {
		cmd = f.Fix.TestRef
	}
	out, err := runCmd(dir, cmd)
	if err != nil {
		return RegressResult{Passed: false, Output: out}, err
	}
	return RegressResult{Passed: true, Output: out}, nil
}
