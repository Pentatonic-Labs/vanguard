package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeStub creates an executable stub script and returns its path.
func writeStub(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hook.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	return path
}

func testPayload() Payload {
	p := sampleProposal()
	return Payload{
		Heartbeat: Heartbeat{Version: "test", Hostname: "testhost", ScanComplete: true, ProposalsTotal: 1},
		Events:    []Event{{TS: time.Now(), Type: TypeNew, Hostname: "testhost", Proposal: &p, Explain: p.Explain()}},
	}
}

func TestRunCommandReceivesValidJSON(t *testing.T) {
	out := filepath.Join(t.TempDir(), "payload.json")
	stub := writeStub(t, "cat > "+out+"\n")

	if err := RunCommand(stub, testPayload()); err != nil {
		t.Fatalf("RunCommand: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("stub did not receive anything: %v", err)
	}
	var got Payload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("payload is not valid JSON: %v\n%s", err, data)
	}
	if !got.Heartbeat.ScanComplete || got.Heartbeat.Hostname != "testhost" {
		t.Fatalf("heartbeat lost: %+v", got.Heartbeat)
	}
	if len(got.Events) != 1 || got.Events[0].Proposal == nil || got.Events[0].Proposal.VulnID == "" {
		t.Fatalf("events lost: %+v", got.Events)
	}
}

func TestRunCommandReportsFailure(t *testing.T) {
	stub := writeStub(t, "echo 'no transport configured' >&2\nexit 3\n")

	err := RunCommand(stub, testPayload())
	if err == nil {
		t.Fatal("a command that exits non-zero must be reported, not swallowed")
	}
}

func TestRunCommandReportsMissingPath(t *testing.T) {
	if err := RunCommand(filepath.Join(t.TempDir(), "nope"), testPayload()); err == nil {
		t.Fatal("a missing command must be reported")
	}
}

func TestPostWebhookSendsPayload(t *testing.T) {
	got := make(chan Payload, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		var p Payload
		if err := json.Unmarshal(body, &p); err != nil {
			t.Errorf("body is not valid JSON: %v", err)
		}
		got <- p
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := PostWebhook(srv.URL, testPayload()); err != nil {
		t.Fatalf("PostWebhook: %v", err)
	}
	select {
	case p := <-got:
		if len(p.Events) != 1 || p.Events[0].Type != TypeNew {
			t.Fatalf("webhook received %+v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("webhook was never called")
	}
}

func TestPostWebhookReportsErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := PostWebhook(srv.URL, testPayload()); err == nil {
		t.Fatal("a 5xx response must be reported")
	}
}
