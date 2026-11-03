package notify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Pentatonic-Labs/vanguard/cvmcore/remediate"
)

func sampleProposal() remediate.Proposal {
	return remediate.Proposal{
		VulnID:    "CVE-0000-0001",
		Severity:  "HIGH",
		CVSS:      8.1,
		Purl:      "pkg:deb/example/openssl",
		Package:   "openssl",
		Installed: "1.0.0",
		Fixed:     "1.0.1",
	}
}

func TestWriteHeartbeatIsCompleteAndAtomic(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	hb := Heartbeat{
		Version:        "test",
		Hostname:       "testhost",
		Started:        time.Now().Add(-2 * time.Second),
		Finished:       time.Now(),
		DurationS:      2,
		ScanComplete:   true,
		ProposalsTotal: 3,
		IntervalS:      3600,
	}
	hb.Events.New = 1

	if err := s.WriteHeartbeat(hb); err != nil {
		t.Fatalf("WriteHeartbeat: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, HeartbeatFile))
	if err != nil {
		t.Fatalf("read heartbeat: %v", err)
	}
	var got Heartbeat
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("heartbeat is not valid JSON: %v\n%s", err, data)
	}
	if got.Hostname != "testhost" || !got.ScanComplete || got.ProposalsTotal != 3 || got.IntervalS != 3600 {
		t.Fatalf("heartbeat round-trip lost fields: %+v", got)
	}
	if got.Events.New != 1 {
		t.Fatalf("event counts lost: %+v", got.Events)
	}

	// The temporary file used for the rename must not be left behind, or a
	// status script globbing the directory reports phantom state.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestAppendEventsCarriesProposal(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	p := sampleProposal()
	events := []Event{
		{TS: time.Now(), Type: TypeNew, Hostname: "testhost", Proposal: &p, Explain: p.Explain()},
		{TS: time.Now(), Type: TypeScanIncomplete, Hostname: "testhost", Explain: "1 feed(s) unavailable"},
	}
	if err := s.AppendEvents(events); err != nil {
		t.Fatalf("AppendEvents: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, EventsFile))
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), data)
	}
	var first Event
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v\n%s", err, lines[0])
	}
	if first.Type != TypeNew || first.Hostname != "testhost" {
		t.Fatalf("unexpected event: %+v", first)
	}
	if first.Proposal == nil || first.Proposal.VulnID != p.VulnID || first.Proposal.Fixed != p.Fixed {
		t.Fatalf("event lost the proposal: %+v", first.Proposal)
	}
	if first.Explain == "" {
		t.Fatal("event lost the explanation")
	}
	if first.TS.IsZero() {
		t.Fatal("event lost its timestamp")
	}

	var second Event
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("line 2 is not valid JSON: %v\n%s", err, lines[1])
	}
	if second.Proposal != nil {
		t.Fatalf("a scan_incomplete event carries no proposal, got %+v", second.Proposal)
	}
}

func TestAppendEventsRotatesKeepingOneGeneration(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	p := sampleProposal()
	event := Event{TS: time.Now(), Type: TypeNew, Hostname: "testhost", Proposal: &p, Explain: p.Explain()}

	// Size the limit to hold one line but not two, so the test does not depend
	// on the exact width of the JSON.
	if err := s.AppendEvents([]Event{event}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	seed, err := os.Stat(filepath.Join(dir, EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	s.RotateAt = seed.Size() + 10

	// One more line trips the limit: it must rotate, not grow past it.
	if err := s.AppendEvents([]Event{event}); err != nil {
		t.Fatalf("append: %v", err)
	}

	rotated := filepath.Join(dir, EventsFile+".1")
	if _, err := os.Stat(rotated); err != nil {
		t.Fatalf("expected a rotated generation at %s: %v", rotated, err)
	}
	current, err := os.Stat(filepath.Join(dir, EventsFile))
	if err != nil {
		t.Fatalf("current log missing: %v", err)
	}
	if current.Size() > s.RotateAt {
		t.Fatalf("current log %d bytes exceeds the %d-byte limit", current.Size(), s.RotateAt)
	}

	// Rotation must move lines aside, not drop them.
	count := func(path string) int {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return len(strings.Split(strings.TrimSpace(string(data)), "\n"))
	}
	if got := count(rotated); got != 1 {
		t.Fatalf("rotated generation holds %d events, want 1", got)
	}
	if got := count(filepath.Join(dir, EventsFile)); got != 1 {
		t.Fatalf("current log holds %d events, want 1", got)
	}

	// Exactly one generation is kept: rotating again replaces .1 and must not
	// start a chain of them.
	if err := s.AppendEvents([]Event{event}); err != nil {
		t.Fatalf("append after rotate: %v", err)
	}
	if _, err := os.Stat(rotated); err != nil {
		t.Fatalf("rotated generation lost: %v", err)
	}
	if _, err := os.Stat(rotated + ".1"); !os.IsNotExist(err) {
		t.Fatalf("only one rotated generation should be kept, found %s.1", rotated)
	}
}

func TestAppendEventsNoopOnEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := NewStore(dir).AppendEvents(nil); err != nil {
		t.Fatalf("AppendEvents(nil): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, EventsFile)); !os.IsNotExist(err) {
		t.Fatal("a cycle with no events must not create the log")
	}
}
