package posture

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEntraCheckPolicyPresent(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v1.0/identity/conditionalAccess/policies" {
			t.Errorf("path = %s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"value":[{"id":"p1"},{"id":"p2"}]}`))
	}))
	defer srv.Close()

	t.Setenv(entraTokenEnv, "entra-token")
	c := NewEntraChecker("tenant-1", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))

	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(res) != 1 || !res[0].Pass {
		t.Fatalf("want one passing result, got %+v", res)
	}
	if gotAuth != "Bearer entra-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}
}

func TestEntraCheckNoPolicies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()

	t.Setenv(entraTokenEnv, "entra-token")
	c := NewEntraChecker("tenant-1", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))

	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(res) != 1 || res[0].Pass {
		t.Fatalf("want a failing result, got %+v", res)
	}
}

func TestEntraCheckNoToken(t *testing.T) {
	t.Setenv(entraTokenEnv, "")
	c := NewEntraChecker("tenant-1")
	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(res) != 1 || res[0].Pass || res[0].Service != "entra" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
