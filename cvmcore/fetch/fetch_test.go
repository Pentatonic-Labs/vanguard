package fetch

import (
	"context"
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
