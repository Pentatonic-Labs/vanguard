// Package notify records what a watch cycle found: a heartbeat file rewritten
// every cycle so an outside observer can tell the loop is alive, and an
// append-only event log so findings survive the terminal scrolling past. The
// same payload is handed to an operator-supplied command or webhook; no
// transport is built in.
package notify

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/Pentatonic-Labs/vanguard/cvmcore/remediate"
)

// Event types written to the log and passed to transports.
const (
	TypeNew            = "new"
	TypePatchAvailable = "patch_available"
	TypeFixWithdrawn   = "fix_withdrawn"
	TypeScanIncomplete = "scan_incomplete"
)

// Names of the files a Store manages.
const (
	HeartbeatFile = "heartbeat.json"
	EventsFile    = "events.jsonl"
)

// DefaultRotateBytes is the size at which the event log is rotated. One
// previous generation is kept as events.jsonl.1.
const DefaultRotateBytes int64 = 50 << 20

// EventCounts is the per-type tally carried in a heartbeat.
type EventCounts struct {
	New            int `json:"new"`
	PatchAvailable int `json:"patch_available"`
	FixWithdrawn   int `json:"fix_withdrawn"`
	ScanIncomplete int `json:"scan_incomplete"`
}

// Add counts one event of the given type.
func (c *EventCounts) Add(typ string) {
	switch typ {
	case TypeNew:
		c.New++
	case TypePatchAvailable:
		c.PatchAvailable++
	case TypeFixWithdrawn:
		c.FixWithdrawn++
	case TypeScanIncomplete:
		c.ScanIncomplete++
	}
}

// Heartbeat proves the loop is alive. It is rewritten at the end of every
// cycle, including cycles that could not complete a scan: "the scan failed" and
// "the watcher died" are different failures and must not look alike.
type Heartbeat struct {
	Version        string      `json:"version"`
	Hostname       string      `json:"hostname"`
	Started        time.Time   `json:"started"`
	Finished       time.Time   `json:"finished"`
	DurationS      float64     `json:"duration_s"`
	ScanComplete   bool        `json:"scan_complete"`
	FeedFailures   int64       `json:"feed_failures"`
	ProposalsTotal int         `json:"proposals_total"`
	Events         EventCounts `json:"events"`
	IntervalS      float64     `json:"interval_s"`
}

// Event is one line of the event log: what changed, and the finding behind it.
// A scan_incomplete event carries no proposal — there was nothing to look at.
type Event struct {
	TS       time.Time           `json:"ts"`
	Type     string              `json:"type"`
	Hostname string              `json:"hostname"`
	Proposal *remediate.Proposal `json:"proposal,omitempty"`
	Explain  string              `json:"explain"`
}

// Payload is the JSON handed to a transport.
type Payload struct {
	Heartbeat Heartbeat `json:"heartbeat"`
	Events    []Event   `json:"events"`
}

// Store owns a watch loop's on-disk state.
type Store struct {
	Dir string
	// RotateAt is the size at which the event log is rotated.
	RotateAt int64
}

// NewStore returns a store rooted at dir, rotating at the default size.
func NewStore(dir string) *Store {
	return &Store{Dir: dir, RotateAt: DefaultRotateBytes}
}

// WriteHeartbeat replaces the heartbeat file atomically: write a temporary file
// in the same directory, then rename. A reader never sees a half-written
// heartbeat, which would look like a truncated or corrupt loop.
func (s *Store) WriteHeartbeat(hb Heartbeat) error {
	data, err := json.MarshalIndent(hb, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".heartbeat-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	// CreateTemp leaves 0600; an operator's status script runs as someone else.
	if err := os.Chmod(name, 0o644); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, filepath.Join(s.Dir, HeartbeatFile))
}

// AppendEvents adds one JSON line per event, rotating the log first if this
// batch would push it past the limit.
func (s *Store) AppendEvents(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	path := filepath.Join(s.Dir, EventsFile)
	if err := s.rotate(path, int64(buf.Len())); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// rotate moves the current log aside once appending would pass the limit,
// keeping a single previous generation.
func (s *Store) rotate(path string, incoming int64) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Size()+incoming <= s.RotateAt {
		return nil
	}
	return os.Rename(path, path+".1")
}
