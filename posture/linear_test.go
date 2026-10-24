package posture

import (
	"context"
	"strings"
	"testing"
)

func TestLinearCheckNoToken(t *testing.T) {
	t.Setenv(linearTokenEnv, "")
	c := NewLinearChecker()
	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(res) != 1 || res[0].Pass || res[0].Service != "linear" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestLinearCheckGETOnlyLimitation(t *testing.T) {
	t.Setenv(linearTokenEnv, "linear-token")
	c := NewLinearChecker()
	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if res[0].Pass {
		t.Fatalf("SSO check must not pass over GET-only transport: %+v", res[0])
	}
	if !strings.Contains(res[0].Detail, "GraphQL over POST") {
		t.Fatalf("detail should explain the GET-only limitation: %q", res[0].Detail)
	}
}
