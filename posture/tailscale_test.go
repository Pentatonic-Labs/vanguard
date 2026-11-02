package posture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakeTailscale builds a commandRunner that answers read-only `tailscale`
// subcommands from canned outputs keyed by the joined args.
func fakeTailscale(outputs map[string]string) commandRunner {
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name != "tailscale" {
			return nil, fmt.Errorf("unexpected command %q", name)
		}
		key := strings.Join(args, " ")
		if out, ok := outputs[key]; ok {
			return []byte(out), nil
		}
		return nil, fmt.Errorf("unexpected tailscale args %q", key)
	}
}

// goodTailscale returns outputs that pass every check, so a test can override
// one key to drive a single failure.
func goodTailscale() map[string]string {
	return map[string]string{
		"version":             "1.106.0\n  tailscale commit: abc\n  go version: go1.26\n",
		"status --json":       `{"BackendState":"Running","Self":{"KeyExpiry":"2026-12-01T00:00:00Z","Capabilities":[],"CapMap":{}}}`,
		"lock status":         "Tailnet Lock is enabled.\n\nThis node's tailnet-lock key: tlpub:...\n",
		"debug prefs":         `{"RunSSH":false,"ControlURL":"https://controlplane.tailscale.com","AppConnector":{"Advertise":false},"AutoUpdate":{"Check":true,"Apply":true}}`,
		"serve status --json": `{"TCP":{}}`,
	}
}

func resultsByCheck(t *testing.T, res []Result) map[string]Result {
	t.Helper()
	m := make(map[string]Result, len(res))
	for _, r := range res {
		m[r.Check] = r
	}
	return m
}

func TestTailscaleNotInstalled(t *testing.T) {
	c := NewTailscaleChecker(WithCommandRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("exec: tailscale: executable file not found in $PATH")
	}))
	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(res) != 1 || res[0].Pass || res[0].Check != "tailscale present" {
		t.Fatalf("want a single failing 'tailscale present' result, got %+v", res)
	}
}

func TestTailscaleVersionAffected(t *testing.T) {
	out := goodTailscale()
	out["version"] = "1.102.2\n  tailscale commit: 6cac918\n"
	c := NewTailscaleChecker(WithCommandRunner(fakeTailscale(out)))

	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	r := resultsByCheck(t, res)["tailscaled version"]
	if r.Pass {
		t.Errorf("version 1.102.2 should fail the version check, got %+v", r)
	}
}

func TestTailscaleVersionNewer(t *testing.T) {
	c := NewTailscaleChecker(WithCommandRunner(fakeTailscale(goodTailscale())))
	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	r := resultsByCheck(t, res)["tailscaled version"]
	if !r.Pass {
		t.Errorf("version 1.106.0 should pass, got %+v", r)
	}
}

func TestTailscaleLockDisabled(t *testing.T) {
	out := goodTailscale()
	out["lock status"] = "Tailnet Lock is NOT enabled.\n"
	c := NewTailscaleChecker(WithCommandRunner(fakeTailscale(out)))

	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if r := resultsByCheck(t, res)["tailnet lock"]; r.Pass {
		t.Errorf("lock disabled should fail, got %+v", r)
	}
}

func TestTailscaleSSHServerRunning(t *testing.T) {
	out := goodTailscale()
	out["debug prefs"] = `{"RunSSH":true,"ControlURL":"https://controlplane.tailscale.com","AppConnector":{"Advertise":false},"AutoUpdate":{"Check":true,"Apply":true}}`
	c := NewTailscaleChecker(WithCommandRunner(fakeTailscale(out)))

	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if r := resultsByCheck(t, res)["tailscale SSH server"]; r.Pass {
		t.Errorf("RunSSH=true should fail the SSH-server check, got %+v", r)
	}
}

func TestTailscaleServeTCPUnixForward(t *testing.T) {
	out := goodTailscale()
	out["serve status --json"] = `{"TCP":{"8080":{"TCPForward":"unix:/run/tailscale/tailscaled.sock"}}}`
	c := NewTailscaleChecker(WithCommandRunner(fakeTailscale(out)))

	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	r := resultsByCheck(t, res)["serve tcp→unix forwards"]
	if r.Pass {
		t.Errorf("TCP→unix forward should fail, got %+v", r)
	}
	if !strings.Contains(r.Detail, "8080") || !strings.Contains(r.Detail, "tailscaled.sock") {
		t.Errorf("detail should name the port and target, got %q", r.Detail)
	}
}

func TestTailscaleServeNoUnixForward(t *testing.T) {
	c := NewTailscaleChecker(WithCommandRunner(fakeTailscale(goodTailscale())))
	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if r := resultsByCheck(t, res)["serve tcp→unix forwards"]; !r.Pass {
		t.Errorf("empty serve config should pass, got %+v", r)
	}
}

func TestTailscaleSelfHostedControlPlane(t *testing.T) {
	out := goodTailscale()
	out["debug prefs"] = `{"RunSSH":false,"ControlURL":"https://headscale.example.com","AppConnector":{"Advertise":false},"AutoUpdate":{"Check":true,"Apply":true}}`
	c := NewTailscaleChecker(WithCommandRunner(fakeTailscale(out)))

	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if r := resultsByCheck(t, res)["headscale control plane"]; r.Pass {
		t.Errorf("self-hosted control plane should fail, got %+v", r)
	}
}

func TestTailscaleNoKeyExpiry(t *testing.T) {
	out := goodTailscale()
	out["status --json"] = `{"BackendState":"Running","Self":{"KeyExpiry":null,"Capabilities":[],"CapMap":{}}}`
	c := NewTailscaleChecker(WithCommandRunner(fakeTailscale(out)))

	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if r := resultsByCheck(t, res)["node key expiry"]; r.Pass {
		t.Errorf("missing key expiry should fail, got %+v", r)
	}
}

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in     string
		want   semver
		wantOK bool
		wantLE bool // want lessEq(1.104.2)
	}{
		{"1.102.2", semver{1, 102, 2}, true, true},
		{"v1.104.2", semver{1, 104, 2}, true, true},
		{"1.104.3", semver{1, 104, 3}, true, false},
		{"1.106.0", semver{1, 106, 0}, true, false},
		{"garbage", semver{}, false, false},
	}
	for _, tc := range cases {
		v, ok := parseSemver(tc.in)
		if ok != tc.wantOK || (ok && v != tc.want) {
			t.Errorf("parseSemver(%q) = %v,%v want %v,%v", tc.in, v, ok, tc.want, tc.wantOK)
		}
		if ok && v.lessEq(tailwormAuditedVersion) != tc.wantLE {
			t.Errorf("parseSemver(%q).lessEq(audited) = %v, want %v", tc.in, v.lessEq(tailwormAuditedVersion), tc.wantLE)
		}
	}
}
