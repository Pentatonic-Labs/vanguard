package posture

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCloudflareCheckAllGood(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/zones/z1/dnssec":
			w.Write([]byte(`{"result":{"status":"active"}}`))
		case "/zones/z1/settings/ssl":
			w.Write([]byte(`{"result":{"value":"full"}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv(cloudflareTokenEnv, "cf-token")
	c := NewCloudflareChecker("z1", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))

	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d results, want 2", len(res))
	}
	if !res[0].Pass || !res[1].Pass {
		t.Fatalf("want both passing, got %+v", res)
	}
}

func TestCloudflareCheckTLSOff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/zones/z1/dnssec":
			w.Write([]byte(`{"result":{"status":"active"}}`))
		case "/zones/z1/settings/ssl":
			w.Write([]byte(`{"result":{"value":"off"}}`))
		}
	}))
	defer srv.Close()

	t.Setenv(cloudflareTokenEnv, "cf-token")
	c := NewCloudflareChecker("z1", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))

	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(res) != 2 || res[0].Pass != true || res[1].Pass != false {
		t.Fatalf("unexpected results: %+v", res)
	}
}

func TestCloudflareCheckNoToken(t *testing.T) {
	t.Setenv(cloudflareTokenEnv, "")
	c := NewCloudflareChecker("z1")
	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(res) != 1 || res[0].Pass || res[0].Service != "cloudflare" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
