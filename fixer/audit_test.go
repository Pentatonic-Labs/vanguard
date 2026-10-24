package fixer

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditLogAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log := NewAuditLog(path)

	if err := log.Append(AuditEntry{FindingID: "id-1", Action: "auto-apply", Result: "applied"}); err != nil {
		t.Fatal(err)
	}
	if err := log.Append(AuditEntry{FindingID: "id-2", Action: "propose", Result: "pr-opened"}); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var entries []AuditEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad JSONL line: %v", err)
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	if len(entries) != 2 || entries[0].FindingID != "id-1" || entries[1].FindingID != "id-2" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	if entries[0].Timestamp == "" {
		t.Fatal("expected timestamp to be filled")
	}
}
