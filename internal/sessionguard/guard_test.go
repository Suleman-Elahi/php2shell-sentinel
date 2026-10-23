package sessionguard_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/sessionguard"
)

func TestSessionGuard_NeutralizesPoisonedAndInflatedSessions(t *testing.T) {
	sessDir := t.TempDir()
	quarantineDir := t.TempDir()

	cfg := config.Default()
	cfg.SessionDirs = []string{sessDir}
	cfg.QuarantineDir = quarantineDir
	cfg.MaxSessionFileBytes = 1024 // 1 KB for test

	logger := audit.NewBufferLogger(io.Discard, "json")
	guard := sessionguard.NewGuard(cfg, logger)

	// 1. Create a legitimate session file
	legitPath := filepath.Join(sessDir, "sess_legit123456")
	if err := os.WriteFile(legitPath, []byte(`user_id|i:42;role|s:6:"member";`), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. Create a Chain A PHP-poisoned session file
	chainAPath := filepath.Join(sessDir, "sess_chaina999")
	if err := os.WriteFile(chainAPath, []byte(`upload_progress_pwn|a:1:{s:4:"name";s:29:"<?php system($_GET['c']); ?>";}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// 3. Create a Chain C handler-mismatch session file
	chainCPath := filepath.Join(sessDir, "sess_chainc888")
	if err := os.WriteFile(chainCPath, []byte(`a:1:{s:16:"upload_progress_";s:30:"|O:4:\"Evil\":1:{s:3:\"cmd\";}";}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// 4. Create a Chain E inflated session file (> 1 KB)
	chainEPath := filepath.Join(sessDir, "sess_chaine777")
	if err := os.WriteFile(chainEPath, make([]byte, 2048), 0o600); err != nil {
		t.Fatal(err)
	}

	mitigated := guard.ScanOnce()
	if mitigated != 3 {
		t.Fatalf("expected 3 poisoned session files to be mitigated, got %d", mitigated)
	}

	// Verify legitimate session file remains untouched
	if _, err := os.Stat(legitPath); err != nil {
		t.Errorf("expected legitimate session file to remain intact: %v", err)
	}

	// Verify all 3 malicious session files were removed
	for _, p := range []string{chainAPath, chainCPath, chainEPath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected malicious session file %s to be deleted", p)
		}
	}

	// Verify forensic samples were saved in quarantineDir
	qEntries, err := os.ReadDir(quarantineDir)
	if err != nil || len(qEntries) != 3 {
		t.Errorf("expected 3 quarantined forensic files, got %d (err=%v)", len(qEntries), err)
	}
}

func TestSessionGuard_UploadProgressArrayIsNotClassifiedAsHandlerMismatch(t *testing.T) {
	sessDir := t.TempDir()

	cfg := config.Default()
	cfg.SessionDirs = []string{sessDir}
	cfg.QuarantineDir = ""

	logger := audit.NewBufferLogger(io.Discard, "json")
	guard := sessionguard.NewGuard(cfg, logger)

	// PHP writes legitimate upload-progress state as a serialized array (`|a:`).
	// This must be reported as P2S-SESS-UPROG, not P2S-SESS-MISMATCH.
	path := filepath.Join(sessDir, "sess_upload_progress")
	content := `upload_progress_abc123|a:1:{s:5:"value";s:1:"x";}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if mitigated := guard.ScanOnce(); mitigated != 1 {
		t.Fatalf("expected one upload-progress session to be mitigated, got %d", mitigated)
	}

	events := logger.RecentEvents(10)
	if len(events) != 1 {
		t.Fatalf("expected exactly one session-guard event, got %d", len(events))
	}
	if events[0].RuleID != "P2S-SESS-UPROG" {
		t.Fatalf("expected rule P2S-SESS-UPROG for serialized upload-progress array, got %q", events[0].RuleID)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected upload-progress session file to be removed, stat err = %v", err)
	}
}
