package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCmdStatusUsesBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	addr := strings.TrimPrefix(server.URL, "http://")
	exitCode := cmdStatus([]string{"-addr", addr, "-token", "test-token"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("cmdStatus() = %d, stderr = %s", exitCode, stderr.String())
	}
	if stdout.String() != `{"status":"ok"}` {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestCmdStatusFailsForUnauthorizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	addr := strings.TrimPrefix(server.URL, "http://")
	exitCode := cmdStatus([]string{"-addr", addr}, &stdout, &stderr)

	if exitCode == 0 {
		t.Fatalf("cmdStatus() = %d, want non-zero", exitCode)
	}
}
