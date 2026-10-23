//go:build integration

package waf_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/agent"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
)

func TestIntegration_ProxyCorpusNeverReachesBackend(t *testing.T) {
	for _, fixture := range loadProxyCorpus(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			var backendRequests atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				backendRequests.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()

			addr, stop := startCorpusAgent(t, backend.URL)
			defer stop()

			request, err := http.NewRequest(fixture.Method, "http://"+addr+fixture.Path, bytes.NewBufferString(fixture.Body))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			for key, value := range fixture.Headers {
				request.Header.Set(key, value)
			}
			if fixture.Chunked {
				request.ContentLength = -1
				request.TransferEncoding = []string{"chunked"}
			}

			client := &http.Client{Timeout: 2 * time.Second}
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("send request: %v", err)
			}
			defer response.Body.Close()

			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusForbidden)
			}
			if rule := response.Header.Get("X-Sentinel-Rule"); !strings.HasPrefix(rule, fixture.RuleID) {
				t.Fatalf("X-Sentinel-Rule = %q, want prefix %q", rule, fixture.RuleID)
			}
			if got := backendRequests.Load(); got != 0 {
				t.Fatalf("backend received %d blocked requests", got)
			}
		})
	}
}

func startCorpusAgent(t *testing.T, backendURL string) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve proxy address: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release proxy address: %v", err)
	}

	cfg := config.Default()
	cfg.ProxyEnabled = true
	cfg.ListenAddr = addr
	cfg.StatusAddr = ""
	cfg.BackendURL = backendURL
	cfg.SessionGuardEnabled = false
	cfg.ProcWatchEnabled = false
	cfg.LogWatchEnabled = false

	ag, err := agent.New(cfg, audit.NewBufferLogger(io.Discard, "json"))
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ag.Run(ctx)
	}()

	for i := 0; i < 20; i++ {
		conn, dialErr := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return addr, func() {
				cancel()
				if runErr := <-done; runErr != nil {
					t.Errorf("agent stopped with error: %v", runErr)
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}

	cancel()
	<-done
	t.Fatalf("agent did not listen on %s", addr)
	return "", nil
}
