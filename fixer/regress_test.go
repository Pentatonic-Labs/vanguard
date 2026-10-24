package fixer

import (
	"errors"
	"testing"

	"github.com/Pentatonic-Labs/vanguard/findings"
)

func TestRegress(t *testing.T) {
	saved := runCmd
	defer func() { runCmd = saved }()

	f := findings.Finding{Fix: &findings.Fix{}}

	runCmd = func(dir, cmd string) (string, error) { return "ok", nil }
	res, err := Regress(f, ".")
	if err != nil || !res.Passed {
		t.Fatalf("expected pass, got %+v err=%v", res, err)
	}

	runCmd = func(dir, cmd string) (string, error) { return "boom", errors.New("exit status 1") }
	res, err = Regress(f, ".")
	if err == nil || res.Passed {
		t.Fatalf("expected fail, got %+v err=%v", res, err)
	}
}

func TestRegressCustomCommand(t *testing.T) {
	saved := runCmd
	defer func() { runCmd = saved }()

	var got string
	runCmd = func(dir, cmd string) (string, error) { got = cmd; return "", nil }
	_, _ = Regress(findings.Finding{Fix: &findings.Fix{TestRef: "pytest"}}, ".")
	if got != "pytest" {
		t.Fatalf("expected custom command, got %q", got)
	}
}
