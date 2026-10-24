package fixer

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// AuditEntry is a single record in the remediation audit trail.
type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	FindingID string `json:"finding_id"`
	Action    string `json:"action"`
	Result    string `json:"result"`
}

// AuditLog appends JSONL audit entries to a file.
type AuditLog struct {
	path string
	mu   sync.Mutex
}

// NewAuditLog returns an AuditLog that appends to path.
func NewAuditLog(path string) *AuditLog {
	return &AuditLog{path: path}
}

// Append records an entry as a single JSON line. A zero Timestamp is replaced
// with the current UTC time.
func (l *AuditLog) Append(e AuditEntry) error {
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}
