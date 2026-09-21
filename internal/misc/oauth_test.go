package misc

import (
	"testing"
)

func TestParseOAuthCallback(t *testing.T) {
	// 1. Standard code & state
	cb, err := ParseOAuthCallback("http://localhost:8317/callback?code=test-code&state=test-state")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cb.Code != "test-code" || cb.State != "test-state" {
		t.Errorf("expected test-code/test-state, got code=%s, state=%s", cb.Code, cb.State)
	}

	// 2. Trae format with authCodeInfo JSON and loginTraceID
	traeURL := "http://127.0.0.1:8317/authorize?loginTraceID=trace-999&authCodeInfo=%7B%22AuthCode%22%3A%22trae-code-888%22%7D"
	cbTrae, err := ParseOAuthCallback(traeURL)
	if err != nil {
		t.Fatalf("unexpected error parsing trae callback: %v", err)
	}
	if cbTrae.Code != "trae-code-888" {
		t.Errorf("expected code trae-code-888, got %s", cbTrae.Code)
	}
	if cbTrae.State != "trace-999" {
		t.Errorf("expected state trace-999, got %s", cbTrae.State)
	}

	// 3. Trae format with direct AuthCode
	traeDirectURL := "http://127.0.0.1:8317/authorize?loginTraceID=trace-777&AuthCode=trae-direct-code"
	cbDirect, err := ParseOAuthCallback(traeDirectURL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cbDirect.Code != "trae-direct-code" || cbDirect.State != "trace-777" {
		t.Errorf("expected trae-direct-code/trace-777, got code=%s, state=%s", cbDirect.Code, cbDirect.State)
	}
}
