package posture

import (
	"errors"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	const token = "supersecret"
	err := redact(errors.New("unauthorized: supersecret"), token)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("token leaked into error: %q", err.Error())
	}
}

func TestRedactEmptyToken(t *testing.T) {
	orig := errors.New("boom")
	if got := redact(orig, ""); got != orig {
		t.Fatalf("empty token should pass the error through unchanged")
	}
}
