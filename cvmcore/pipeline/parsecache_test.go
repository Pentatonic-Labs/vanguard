package pipeline

import (
	"testing"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

func TestParsedCacheRoundTrip(t *testing.T) {
	pc := parsedCache{dir: t.TempDir()}
	vulns := []cvmcore.Vuln{
		{ID: "X", Severity: "high", Affected: []cvmcore.VersionRange{{Ecosystem: "deb", Fixed: "1.2"}}},
	}
	if err := pc.save("key", vulns); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, ok := pc.load("key")
	if !ok {
		t.Fatalf("load: cache miss")
	}
	if len(got) != 1 || got[0].ID != "X" || len(got[0].Affected) != 1 || got[0].Affected[0].Fixed != "1.2" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestParsedCacheMiss(t *testing.T) {
	pc := parsedCache{dir: t.TempDir()}
	if _, ok := pc.load("nonexistent"); ok {
		t.Fatalf("expected miss for nonexistent key")
	}
}
