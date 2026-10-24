package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetCachedConditional(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte("hello world"))
	}))
	defer srv.Close()

	c := NewClient(5*time.Second, WithCacheDir(t.TempDir()), WithMinDelay(0))
	url := srv.URL + "/export"

	b1, err := c.getCached(context.Background(), url)
	if err != nil {
		t.Fatalf("first getCached: %v", err)
	}
	b2, err := c.getCached(context.Background(), url)
	if err != nil {
		t.Fatalf("second getCached: %v", err)
	}
	if string(b1) != "hello world" || string(b2) != "hello world" {
		t.Errorf("unexpected bodies: %q %q", b1, b2)
	}
	if requests != 2 {
		t.Errorf("want 2 requests (200 then 304), got %d", requests)
	}
}

func TestGetCachedNoCacheDir(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("no-cache"))
	}))
	defer srv.Close()

	c := NewClient(5*time.Second, WithMinDelay(0)) // no cache dir
	b, err := c.getCached(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatalf("getCached: %v", err)
	}
	if string(b) != "no-cache" {
		t.Errorf("got %q, want no-cache", b)
	}
}
