package agent_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
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

func TestAgent_ProxyReadTimeoutClosesSlowMultipartUpload(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	addr := reserveTCPAddr(t)
	cfg := config.Default()
	cfg.ProxyEnabled = true
	cfg.ListenAddr = addr
	cfg.StatusAddr = ""
	cfg.BackendURL = backend.URL
	cfg.RequestReadTimeout = 2 * time.Second
	cfg.MultipartChunkTimeout = 100 * time.Millisecond
	cfg.SessionGuardEnabled = false
	cfg.ProcWatchEnabled = false
	cfg.LogWatchEnabled = false

	logger := audit.NewBufferLogger(io.Discard, "json")
	ag, err := agent.New(cfg, logger)
	if err != nil {
		t.Fatalf("agent.New failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ag.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("agent exited with unexpected error: %v", err)
		}
	})

	conn := dialAgent(t, addr)
	defer conn.Close()
	if _, err := io.WriteString(conn, "POST /upload.php HTTP/1.1\r\n"+
		"Host: sentinel.test\r\n"+
		"Content-Type: multipart/form-data; boundary=test\r\n"+
		"Content-Length: 4096\r\n\r\n"+
		"--test\r\n"); err != nil {
		t.Fatalf("write partial request: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	started := time.Now()
	n, err := conn.Read(make([]byte, 1))
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("slow multipart connection was not closed before client timeout: %v", err)
	}
	if n == 0 && err == nil {
		t.Fatal("slow multipart connection remained usable after request deadline")
	}
	if elapsed := time.Since(started); elapsed > 750*time.Millisecond {
		t.Fatalf("slow multipart connection closed too late: %s", elapsed)
	}
}

func reserveTCPAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP address: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved listener: %v", err)
	}
	return addr
}

func dialAgent(t *testing.T, addr string) net.Conn {
	t.Helper()
	var lastErr error
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("dial agent at %s: %v", addr, lastErr)
	return nil
}
