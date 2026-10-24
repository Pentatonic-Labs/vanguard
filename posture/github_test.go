package posture

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGitHubCheckAllMembersHave2FA(t *testing.T) {
	var gotAuth, gotFilter string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/orgs/acme/members" {
			t.Errorf("path = %s, want /orgs/acme/members", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotFilter = r.URL.Query().Get("filter")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	t.Setenv(githubTokenEnv, "gh-token")
	c := NewGitHubChecker("acme", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))

	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if !res[0].Pass {
		t.Errorf("want Pass=true, got %+v", res[0])
	}
	if gotAuth != "Bearer gh-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer gh-token")
	}
	if gotFilter != "2fa_disabled" {
		t.Errorf("filter = %q, want %q", gotFilter, "2fa_disabled")
	}
}

func TestGitHubCheckMembersMissing2FA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"login":"alice"},{"login":"bob"}]`))
	}))
	defer srv.Close()

	t.Setenv(githubTokenEnv, "gh-token")
	c := NewGitHubChecker("acme", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))

	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(res) != 1 || res[0].Pass {
		t.Fatalf("want a failing result, got %+v", res)
	}
}

func TestGitHubCheckNoToken(t *testing.T) {
	t.Setenv(githubTokenEnv, "")
	c := NewGitHubChecker("acme")
	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(res) != 1 || res[0].Pass || res[0].Service != "github" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
