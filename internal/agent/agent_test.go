package agent_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/agent"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
)

func TestAgent_LifecycleAndStatusEndpoint(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("HELLO_PHP"))
	}))
	defer backend.Close()

	cfg := config.Default()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.StatusAddr = "127.0.0.1:19095"
	cfg.BackendURL = backend.URL
	cfg.ProxyEnabled = false
	cfg.SessionGuardEnabled = false
	cfg.ProcWatchEnabled = false
	cfg.LogWatchEnabled = false

	logger := audit.NewBufferLogger(io.Discard, "json")
	ag, err := agent.New(cfg, logger)
	if err != nil {
		t.Fatalf("agent.New failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ag.Run(ctx)
	}()

	// Poll status endpoint until ready
	client := &http.Client{Timeout: 500 * time.Millisecond}
	var statusResp agent.StatusReport
	ready := false
	for i := 0; i < 20; i++ {
		resp, err := client.Get("http://127.0.0.1:19095/status")
		if err == nil {
			_ = json.NewDecoder(resp.Body).Decode(&statusResp)
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	if !ready {
		cancel()
		t.Fatalf("status endpoint did not become ready")
	}

	if statusResp.Agent != "php2shell-sentinel" {
		t.Errorf("unexpected agent name %q", statusResp.Agent)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("agent exited with unexpected error: %v", err)
	}
}
