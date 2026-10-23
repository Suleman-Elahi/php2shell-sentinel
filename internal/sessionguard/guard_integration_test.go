//go:build integration

package sessionguard_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/sessionguard"
)

func TestIntegration_SessionGuardRemovesNewPoisonedSession(t *testing.T) {
	sessionDir := t.TempDir()
	quarantineDir := t.TempDir()

	cfg := config.Default()
	cfg.SessionDirs = []string{sessionDir}
	cfg.QuarantineDir = quarantineDir
	cfg.SessionPollInterval = 5 * time.Millisecond
	cfg.DeletePoisonedSess = true

	guard := sessionguard.NewGuard(cfg, audit.NewBufferLogger(io.Discard, "json"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		guard.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	path := filepath.Join(sessionDir, "sess_integration_safe")
	if err := os.WriteFile(path, []byte(`upload_progress_safe|s:24:"<?php echo 'marker'; ?>";`), 0o600); err != nil {
		t.Fatalf("write poisoned session fixture: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			t.Fatalf("stat session fixture: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("session guard did not remove poisoned session fixture")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
