package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Pentatonic-Labs/vanguard/cvmcore/remediate"
	"github.com/Pentatonic-Labs/vanguard/notify"
)

func TestDiffFixed(t *testing.T) {
	prev := map[string]string{
		"A": "",    // was unfixed
		"B": "1.0", // was fixed
		"C": "2.0", // was fixed
	}
	current := map[string]string{
		"A": "1.2", // -> patch became available
		"B": "1.0", // -> unchanged
		"C": "",    // -> fix withdrawn
		"D": "",    // -> brand new
	}

	newKeys, nowFixed, withdrawn := diffFixed(prev, current)

	if !reflect.DeepEqual(newKeys, []string{"D"}) {
		t.Fatalf("newKeys = %v, want [D]", newKeys)
	}
	if !reflect.DeepEqual(nowFixed, []string{"A"}) {
		t.Fatalf("nowFixed = %v, want [A]", nowFixed)
	}
	if !reflect.DeepEqual(withdrawn, []string{"C"}) {
		t.Fatalf("withdrawn = %v, want [C]", withdrawn)
	}
}

// A feed failure is not "no vulnerabilities". On a host whose DNS died, both
// feeds fail, the scan finds nothing, and recording that as a baseline reports a
// permanently clean box — the exact class of silent-stale-state this tool exists
// to prevent. The guard is that a run which lost a feed never baselines.
func TestFeedFailureIsNotACleanBaseline(t *testing.T) {
	if shouldRecordBaseline(0) != true {
		t.Error("a scan with no feed failures must baseline")
	}
	if shouldRecordBaseline(1) != false {
		t.Error("a scan that lost a feed must NOT baseline — that records an empty result as clean")
	}
}

// newTestWatcher returns a watcher rooted in a throwaway directory, so a test
// can drive whole cycles without touching the real cache.
func newTestWatcher(t *testing.T) *watcher {
	t.Helper()
	dir := t.TempDir()
	return &watcher{
		store:     notify.NewStore(dir),
		statePath: filepath.Join(dir, "watch.json"),
		interval:  time.Hour,
		hostname:  "testhost",
		prev:      map[string]string{},
	}
}

func readHeartbeat(t *testing.T, w *watcher) notify.Heartbeat {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(w.store.Dir, notify.HeartbeatFile))
	if err != nil {
		t.Fatalf("heartbeat not written: %v", err)
	}
	var hb notify.Heartbeat
	if err := json.Unmarshal(data, &hb); err != nil {
		t.Fatalf("heartbeat is not valid JSON: %v\n%s", err, data)
	}
	return hb
}

func readEvents(t *testing.T, w *watcher) []notify.Event {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(w.store.Dir, notify.EventsFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read events: %v", err)
	}
	var events []notify.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e notify.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("event line is not valid JSON: %v\n%s", err, line)
		}
		events = append(events, e)
	}
	return events
}

func proposal(vulnID, pkg, fixed string) remediate.Proposal {
	return remediate.Proposal{
		VulnID:    vulnID,
		Severity:  "HIGH",
		CVSS:      8.1,
		Purl:      "pkg:deb/example/" + pkg,
		Package:   pkg,
		Installed: "1.0.0",
		Fixed:     fixed,
	}
}

// A cycle that completed must leave a heartbeat behind even when nothing
// changed: the heartbeat is the only proof the loop is still running.
func TestCycleWritesHeartbeatOnCompleteScan(t *testing.T) {
	w := newTestWatcher(t)
	w.cycle(func() ([]remediate.Proposal, int64, error) {
		return []remediate.Proposal{proposal("CVE-0000-0001", "openssl", "")}, 0, nil
	})

	hb := readHeartbeat(t, w)
	if !hb.ScanComplete {
		t.Fatal("scan_complete = false for a scan that succeeded")
	}
	if hb.Hostname != "testhost" {
		t.Fatalf("hostname = %q", hb.Hostname)
	}
	if hb.ProposalsTotal != 1 {
		t.Fatalf("proposals_total = %d, want 1", hb.ProposalsTotal)
	}
	if hb.IntervalS != 3600 {
		t.Fatalf("interval_s = %v, want 3600", hb.IntervalS)
	}
	if hb.Started.IsZero() || hb.Finished.IsZero() || hb.Finished.Before(hb.Started) {
		t.Fatalf("bad timestamps: %+v", hb)
	}
	if hb.Version == "" {
		t.Fatal("heartbeat carries no version")
	}
	if hb.Events.New != 1 {
		t.Fatalf("events.new = %d, want 1", hb.Events.New)
	}

	events := readEvents(t, w)
	if len(events) != 1 || events[0].Type != notify.TypeNew {
		t.Fatalf("events = %+v, want one new event", events)
	}
	if events[0].Proposal == nil || events[0].Proposal.VulnID != "CVE-0000-0001" {
		t.Fatalf("event lost the proposal: %+v", events[0].Proposal)
	}
}

// An incomplete scan is not a quiet cycle, and the heartbeat has to say so.
func TestCycleWritesHeartbeatOnIncompleteScan(t *testing.T) {
	w := newTestWatcher(t)
	w.cycle(func() ([]remediate.Proposal, int64, error) {
		return nil, 2, nil
	})

	hb := readHeartbeat(t, w)
	if hb.ScanComplete {
		t.Fatal("scan_complete = true for a scan that lost feeds")
	}
	if hb.FeedFailures != 2 {
		t.Fatalf("feed_failures = %d, want 2", hb.FeedFailures)
	}
	events := readEvents(t, w)
	if len(events) != 1 || events[0].Type != notify.TypeScanIncomplete {
		t.Fatalf("events = %+v, want one scan_incomplete event", events)
	}
	if hb.Events.ScanIncomplete != 1 {
		t.Fatalf("heartbeat counts = %+v, want one incomplete", hb.Events)
	}
	// A partial scan must still not baseline.
	if fileExists(w.statePath) {
		t.Fatal("an incomplete scan wrote a baseline")
	}
}

// The first cycle records a baseline: no events, but a heartbeat.
func TestFirstRunWritesHeartbeatAndNoEvents(t *testing.T) {
	w := newTestWatcher(t)
	w.firstRun = true
	w.cycle(func() ([]remediate.Proposal, int64, error) {
		return []remediate.Proposal{proposal("CVE-0000-0001", "openssl", "")}, 0, nil
	})

	if hb := readHeartbeat(t, w); !hb.ScanComplete || hb.ProposalsTotal != 1 {
		t.Fatalf("baseline heartbeat = %+v", hb)
	}
	if events := readEvents(t, w); len(events) != 0 {
		t.Fatalf("a baseline must emit no events, got %+v", events)
	}
}

// An unchanged second cycle reports nothing. Diffing against the map loaded at
// startup rather than the cycle's own result turns the log into a repeat of
// "new" for every finding, every interval, for ever.
func TestUnchangedCycleEmitsNoEvents(t *testing.T) {
	w := newTestWatcher(t)
	scan := func() ([]remediate.Proposal, int64, error) {
		return []remediate.Proposal{proposal("CVE-0000-0001", "openssl", "")}, 0, nil
	}
	w.cycle(scan)
	w.cycle(scan)

	if events := readEvents(t, w); len(events) != 1 {
		t.Fatalf("got %d events, want 1 (first new only): %+v", len(events), events)
	}
	if hb := readHeartbeat(t, w); hb.Events.New != 0 {
		t.Fatalf("second cycle counted %d new events", hb.Events.New)
	}
}

// A transport that fails must not end the watch loop.
func TestFailingNotifyCommandDoesNotStopTheLoop(t *testing.T) {
	w := newTestWatcher(t)
	stub := filepath.Join(t.TempDir(), "hook.sh")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w.notifyCmd = stub

	w.cycle(func() ([]remediate.Proposal, int64, error) {
		return []remediate.Proposal{proposal("CVE-0000-0001", "openssl", "")}, 0, nil
	})
	w.cycle(func() ([]remediate.Proposal, int64, error) {
		return []remediate.Proposal{
			proposal("CVE-0000-0001", "openssl", ""),
			proposal("CVE-0000-0002", "bash", ""),
		}, 0, nil
	})

	hb := readHeartbeat(t, w)
	if hb.ProposalsTotal != 2 {
		t.Fatalf("the cycle after a failed notify did not run: %+v", hb)
	}
	if hb.Events.New != 1 {
		t.Fatalf("events.new = %d, want 1", hb.Events.New)
	}
}

// A cycle that could not scan at all must wake a transport too. Otherwise a box
// that errors on every interval is only visible as a heartbeat that stops
// changing — which looks the same as a quiet box.
func TestFatalScanErrorNotifies(t *testing.T) {
	dir := t.TempDir()
	received := filepath.Join(dir, "payload.json")
	stub := filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\ncat > "+received+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := newTestWatcher(t)
	w.notifyCmd = stub

	scanErr := errors.New(strings.Repeat("feed unavailable: connection refused ", 40))
	w.cycle(func() ([]remediate.Proposal, int64, error) {
		return nil, 1, scanErr
	})

	events := readEvents(t, w)
	if len(events) != 1 || events[0].Type != notify.TypeScanIncomplete {
		t.Fatalf("events = %+v, want one scan_incomplete event", events)
	}
	if !strings.Contains(events[0].Explain, "feed unavailable: connection refused") {
		t.Fatalf("event does not carry the error text: %q", events[0].Explain)
	}
	if n := len([]rune(events[0].Explain)); n > 300 {
		t.Fatalf("explain is %d chars, want ~300 or less", n)
	}

	hb := readHeartbeat(t, w)
	if hb.ScanComplete {
		t.Fatal("scan_complete = true for a cycle that errored")
	}
	if hb.Events.ScanIncomplete != 1 {
		t.Fatalf("heartbeat counts = %+v, want one incomplete", hb.Events)
	}

	data, err := os.ReadFile(received)
	if err != nil {
		t.Fatalf("the notify command was not called: %v", err)
	}
	var payload notify.Payload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("payload is not valid JSON: %v\n%s", err, data)
	}
	if len(payload.Events) != 1 || payload.Events[0].Type != notify.TypeScanIncomplete {
		t.Fatalf("hook received %+v, want one scan_incomplete event", payload.Events)
	}
	if payload.Heartbeat.ScanComplete {
		t.Fatal("hook was told the scan completed")
	}
}
