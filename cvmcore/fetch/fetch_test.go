package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchKEVReturnsBody(t *testing.T) {
	const want = `{"vulnerabilities":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua == "" {
			t.Errorf("missing User-Agent header")
		}
		if r.URL.Path != "/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(want))
	}))
	defer srv.Close()

	c := NewClient(5*time.Second, WithMinDelay(0))
	c.KEVURL = srv.URL

	body, err := c.FetchKEV(context.Background())
	if err != nil {
		t.Fatalf("FetchKEV: %v", err)
	}
	if string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

func TestFetchTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(10*time.Millisecond, WithMinDelay(0))
	c.KEVURL = srv.URL

	if _, err := c.FetchKEV(context.Background()); err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestQueryBatchRequestShape(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"OSV-A"}]}]}`))
	}))
	defer srv.Close()

	c := NewClient(5*time.Second, WithMinDelay(0))
	c.OSVQueryURL = srv.URL

	body, err := c.QueryBatch(context.Background(), []string{"pkg:deb/a@1.0", "pkg:deb/b@2.0"})
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}

	var sent struct {
		Queries []struct {
			Package struct {
				Purl string `json:"purl"`
			} `json:"package"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(gotBody, &sent); err != nil {
		t.Fatalf("sent body is not valid JSON: %v", err)
	}
	if len(sent.Queries) != 2 {
		t.Fatalf("queries len = %d, want 2", len(sent.Queries))
	}
	if sent.Queries[0].Package.Purl != "pkg:deb/a@1.0" || sent.Queries[1].Package.Purl != "pkg:deb/b@2.0" {
		t.Errorf("purls = %q, %q", sent.Queries[0].Package.Purl, sent.Queries[1].Package.Purl)
	}

	var out struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("returned body is not valid JSON: %v", err)
	}
	if len(out.Results) != 1 {
		t.Errorf("results len = %d, want 1", len(out.Results))
	}
}

func TestQueryBatchChunks(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var q struct {
			Queries []json.RawMessage `json:"queries"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &q)
		results := make([]json.RawMessage, 0, len(q.Queries))
		for range q.Queries {
			results = append(results, json.RawMessage(`{"vulns":[]}`))
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
	defer srv.Close()

	c := NewClient(5*time.Second, WithMinDelay(0))
	c.OSVQueryURL = srv.URL

	purls := make([]string, 1001)
	for i := range purls {
		purls[i] = fmt.Sprintf("pkg:deb/p%d@1.0", i)
	}
	body, err := c.QueryBatch(context.Background(), purls)
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if requests != 2 {
		t.Errorf("requests = %d, want 2 (1000 + 1)", requests)
	}
	var out struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("returned body invalid: %v", err)
	}
	if len(out.Results) != 1001 {
		t.Errorf("results = %d, want 1001", len(out.Results))
	}
}

func TestFetchNVDRecentPagination(t *testing.T) {
	var startIndexes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startIndexes = append(startIndexes, r.URL.Query().Get("startIndex"))
		if r.URL.Query().Get("lastModStartDate") == "" {
			t.Error("missing lastModStartDate")
		}
		if r.URL.Query().Get("resultsPerPage") != "2" {
			t.Errorf("resultsPerPage = %q, want 2", r.URL.Query().Get("resultsPerPage"))
		}
		w.WriteHeader(http.StatusOK)
		switch r.URL.Query().Get("startIndex") {
		case "0":
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"A"}},{"cve":{"id":"B"}}]}`))
		case "2":
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"C"}}]}`))
		default:
			t.Errorf("unexpected startIndex %q", r.URL.Query().Get("startIndex"))
		}
	}))
	defer srv.Close()

	c := NewClient(5*time.Second, WithMinDelay(0))
	c.NVDURL = srv.URL
	c.NVDPageSize = 2

	body, err := c.FetchNVDRecent(context.Background(), time.Now().Add(-48*time.Hour))
	if err != nil {
		t.Fatalf("FetchNVDRecent: %v", err)
	}
	var out struct {
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("returned body invalid: %v", err)
	}
	if len(out.Vulnerabilities) != 3 {
		t.Errorf("vulnerabilities = %d, want 3", len(out.Vulnerabilities))
	}
	if len(startIndexes) != 2 || startIndexes[0] != "0" || startIndexes[1] != "2" {
		t.Errorf("startIndexes = %v, want [0 2]", startIndexes)
	}
}
