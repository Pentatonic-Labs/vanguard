package posture

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testRuntime returns a Runtime over a fixture root with a fixed clock and an
// injected apt simulation, so no test reads the host it runs on.
func testRuntime(t *testing.T, root string, aptOut string, aptErr error) *Runtime {
	t.Helper()
	r := NewRuntime(filepath.Join("testdata", root))
	r.Now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.Local)
	r.RunApt = func(context.Context, time.Duration) ([]byte, error) {
		return []byte(aptOut), aptErr
	}
	return r
}

func byCheck(results []Result, check string) []Result {
	var out []Result
	for _, r := range results {
		if r.Check == check {
			out = append(out, r)
		}
	}
	return out
}

func TestUnsandboxedBrowsers(t *testing.T) {
	results := testRuntime(t, "dirty", "", nil).UnsandboxedBrowsers()

	if len(results) != 3 {
		t.Fatalf("got %d findings, want 3 (one per browser root): %+v", len(results), results)
	}
	// pids 102 and 202 carry --no-sandbox but are renderer/zygote children of
	// 101 and 201; pid 401 has no --no-sandbox at all.
	for _, want := range []struct {
		pid      string
		severity string
		evidence []string
	}{
		{"101", "high", []string{`user "alice"`, `/usr/bin/chrome`, `parent "python3"`, "remote debugging enabled"}},
		{"201", "high", []string{`user "builder"`, "SSH keys"}},
		{"301", "medium", []string{`user "alice"`}},
	} {
		var found *Result
		for i, r := range results {
			if strings.Contains(r.Detail, "pid "+want.pid+",") {
				found = &results[i]
			}
		}
		if found == nil {
			t.Fatalf("no finding for pid %s in %+v", want.pid, results)
		}
		if found.Severity != want.severity {
			t.Errorf("pid %s severity = %q, want %q", want.pid, found.Severity, want.severity)
		}
		if found.Pass {
			t.Errorf("pid %s finding must not pass", want.pid)
		}
		for _, evidence := range want.evidence {
			if !strings.Contains(found.Detail, evidence) {
				t.Errorf("pid %s detail = %q, want it to contain %q", want.pid, found.Detail, evidence)
			}
		}
		if want.severity == "high" && !strings.Contains(strings.ToLower(found.Fix), "no-sandbox") {
			t.Errorf("pid %s fix = %q, want it to name --no-sandbox", want.pid, found.Fix)
		}
	}
}

func TestWildcardListeners(t *testing.T) {
	results := testRuntime(t, "dirty", "", nil).WildcardListeners()

	want := map[string]string{
		"port 8000":  `user "root"`,
		"port 8787":  "[::]",
		"port 9222":  `user "alice"`,
		"port 34567": `user "node"`,
	}
	for port, evidence := range want {
		if !strings.Contains(join(results), port+" on") {
			t.Errorf("no wildcard finding for %s: %+v", port, results)
		}
		for _, r := range results {
			if strings.HasPrefix(r.Detail, port+" on") && !strings.Contains(r.Detail, evidence) {
				t.Errorf("%s detail = %q, want it to contain %q", port, r.Detail, evidence)
			}
		}
	}
	// 8043 is loopback-only, 40000 is a high port owned by root, 8100 is an
	// IPv4-mapped loopback listener and 41000 is not in LISTEN state.
	for _, unwanted := range []string{"port 8043", "port 40000", "port 8100", "port 41000"} {
		if strings.Contains(join(results), unwanted+" on") {
			t.Errorf("unexpected finding for %s: %+v", unwanted, results)
		}
	}
	if len(results) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(results), len(want), results)
	}
	for _, r := range results {
		if r.Severity != "high" {
			t.Errorf("port finding severity = %q, want high (%+v)", r.Severity, r)
		}
	}
	// The socket inode is mapped back to the owning process.
	if !strings.Contains(join(results), "pid 900 (python3)") {
		t.Errorf("no evidence of the owning process: %+v", results)
	}
}

func TestPatchLag(t *testing.T) {
	aptOut := strings.Join([]string{
		"NOTE: This is only a simulation!",
		"Inst openssl [3.0.13-0] (3.0.13-1 Ubuntu:24.04/noble-updates [amd64])",
		"Inst libssl3 [3.0.13-0] (3.0.13-1 Ubuntu:24.04/noble-security [amd64])",
		"Inst curl [8.5.0-1] (8.5.0-2 Ubuntu:24.04/noble-security [amd64])",
		"Inst vim [9.1.0-1] (9.1.0-2 Ubuntu:24.04/noble-updates [amd64])",
	}, "\n")
	results := testRuntime(t, "dirty", aptOut, nil).PatchLag(context.Background())

	unattended := byCheck(results, "unattended upgrades")
	if len(unattended) != 1 || !unattended[0].Pass {
		t.Fatalf("unattended upgrades = %+v, want one passing result", unattended)
	}

	security := byCheck(results, "pending security updates")
	if len(security) != 1 {
		t.Fatalf("got %d security results, want 1", len(security))
	}
	got := security[0]
	if got.Pass {
		t.Errorf("security result must fail: %+v", got)
	}
	if !strings.Contains(got.Detail, "2 security update(s) pending") {
		t.Errorf("detail = %q, want 2 pending security updates", got.Detail)
	}
	// The fixture's last upgrade is 2026-10-24, 10 days before the fixed clock.
	if !strings.Contains(got.Detail, "last upgrade 10 day(s) ago") {
		t.Errorf("detail = %q, want the last upgrade age", got.Detail)
	}
	if got.Severity != "high" {
		t.Errorf("severity = %q, want high for security updates older than 7 days", got.Severity)
	}
}

func TestPatchLagUnknownWhenAptFails(t *testing.T) {
	results := testRuntime(t, "dirty", "", errors.New("E: Could not get lock /var/lib/dpkg/lock-frontend")).PatchLag(context.Background())

	security := byCheck(results, "pending security updates")
	if len(security) != 1 {
		t.Fatalf("got %d security results, want 1", len(security))
	}
	if !security[0].Pass {
		t.Errorf("a locked apt is unknown, not a failure: %+v", security[0])
	}
	if !strings.Contains(security[0].Detail, "unknown") {
		t.Errorf("detail = %q, want it to say unknown", security[0].Detail)
	}
}

func TestPatchLagUnknownWhenDpkgIsASnapshot(t *testing.T) {
	// Files come from a snapshot but RunApt is the live apt-get: the count must
	// be unknown rather than borrowed from this host's package database.
	r := NewRuntime(filepath.Join("testdata", "clean"))
	r.Now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.Local)

	security := byCheck(r.PatchLag(context.Background()), "pending security updates")
	if len(security) != 1 {
		t.Fatalf("got %d security results, want 1", len(security))
	}
	if !security[0].Pass || !strings.Contains(security[0].Detail, "unknown") {
		t.Errorf("snapshot result = %+v, want a passing unknown", security[0])
	}
}

func TestPatchLagSkipsNonDebian(t *testing.T) {
	r := testRuntime(t, "clean", "", nil)
	r.Root = t.TempDir() // no dpkg database at all

	results := r.PatchLag(context.Background())
	if len(results) != 1 || !results[0].Pass {
		t.Fatalf("got %+v, want a single skipped result", results)
	}
	if !strings.Contains(results[0].Detail, "not Debian/Ubuntu") {
		t.Errorf("detail = %q, want it to explain the skip", results[0].Detail)
	}
}

func TestPendingReboot(t *testing.T) {
	results := testRuntime(t, "dirty", "", nil).PendingReboot()

	if len(results) != 2 {
		t.Fatalf("got %d findings, want 2 (flag file and newer kernel): %+v", len(results), results)
	}
	joined := join(results)
	if !strings.Contains(joined, "reboot-required") {
		t.Errorf("no finding for the reboot-required flag: %+v", results)
	}
	if !strings.Contains(joined, "newest installed 6.8.0-51-generic") {
		t.Errorf("no finding for the newer installed kernel: %+v", results)
	}
	if strings.Contains(joined, "dbgsym") {
		t.Errorf("a debug-symbol package must not count as an installed kernel: %+v", results)
	}
	for _, r := range results {
		if r.Pass || r.Severity != "medium" {
			t.Errorf("result = %+v, want a medium failure", r)
		}
	}
}

func TestCleanHostPassesEveryCheck(t *testing.T) {
	results := testRuntime(t, "clean", "0 upgraded, 0 newly installed.", nil).Results(context.Background())

	for _, r := range results {
		if !r.Pass {
			t.Errorf("%s/%s failed on a clean host: %s", r.Service, r.Check, r.Detail)
		}
		if r.Service != ServiceName {
			t.Errorf("service = %q, want %q", r.Service, ServiceName)
		}
	}
	if len(results) != 5 {
		t.Errorf("got %d results, want one per check (unattended upgrades and pending security updates are separate): %+v", len(results), results)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"6.8.0-51-generic", "6.8.0-45-generic", 1},
		{"6.8.0-45-generic", "6.8.0-51-generic", -1},
		{"6.8.0-51-generic", "6.8.0-51-generic", 0},
		{"6.10.0-1-generic", "6.9.0-9-generic", 1},
		{"6.8.0-051-generic", "6.8.0-51-generic", 0},
	} {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestParseListenLine(t *testing.T) {
	if _, ok := parseListenLine("   0: 00000000:1F40 00000000:0000 01 00000000:00000000 00:00000000 00000000 0 0 8000 1"); ok {
		t.Error("a non-LISTEN row must not parse as a listener")
	}
	l, ok := parseListenLine("   0: 00000000:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 8000 1 0000000000000000 100 0 0 10 0")
	if !ok || l.port != 8000 || !l.wildcard || l.address != "0.0.0.0" || l.inode != "8000" {
		t.Errorf("parsed %+v, ok=%v; want port 8000 wildcard on 0.0.0.0", l, ok)
	}
	l, ok = parseListenLine("   0: 0100007F:1F6B 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 8043 1")
	if !ok || l.wildcard {
		t.Errorf("loopback listener parsed as wildcard: %+v", l)
	}
}

func join(results []Result) string {
	var b strings.Builder
	for _, r := range results {
		b.WriteString(r.Check)
		b.WriteString(" | ")
		b.WriteString(r.Detail)
		b.WriteString("\n")
	}
	return b.String()
}
