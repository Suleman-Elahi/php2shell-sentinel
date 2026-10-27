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

func TestSessionGuard_ScrubsUploadProgressInPlacePreservingUserSession(t *testing.T) {
	sessDir := t.TempDir()
	quarantineDir := t.TempDir()

	cfg := config.Default()
	cfg.SessionDirs = []string{sessDir}
	cfg.QuarantineDir = quarantineDir

	logger := audit.NewBufferLogger(io.Discard, "json")
	guard := sessionguard.NewGuard(cfg, logger)

	// Active user session with both login keys and an upload_progress_ entry
	path := filepath.Join(sessDir, "sess_active_user")
	original := `user_id|i:42;upload_progress_chunk1|a:2:{s:14:"content_length";i:1048576;s:4:"done";b:0;}role|s:6:"member";`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	if mitigated := guard.ScanOnce(); mitigated != 1 {
		t.Fatalf("expected 1 session file to be scrubbed in place, got %d", mitigated)
	}

	// File must still exist with user_id and role intact, and upload_progress_ removed
	afterBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected session file to remain on disk after in-place scrub: %v", err)
	}
	want := `user_id|i:42;role|s:6:"member";`
	if string(afterBytes) != want {
		t.Fatalf("scrubbed session content = %q, want %q", string(afterBytes), want)
	}

	// Second scan must not re-trigger on the already cleaned file
	if mitigated := guard.ScanOnce(); mitigated != 0 {
		t.Fatalf("expected 0 interventions on second scan of scrubbed session, got %d", mitigated)
	}
}

func TestSessionGuard_AllowBenignUploadProgressOption(t *testing.T) {
	sessDir := t.TempDir()

	cfg := config.Default()
	cfg.SessionDirs = []string{sessDir}
	cfg.QuarantineDir = ""
	cfg.AllowBenignUploadProgress = true

	logger := audit.NewBufferLogger(io.Discard, "json")
	guard := sessionguard.NewGuard(cfg, logger)

	benignPath := filepath.Join(sessDir, "sess_resumable")
	benign := `user_id|i:7;upload_progress_vid|a:1:{s:4:"done";b:0;}`
	if err := os.WriteFile(benignPath, []byte(benign), 0o600); err != nil {
		t.Fatal(err)
	}

	poisonPath := filepath.Join(sessDir, "sess_poisoned_uprog")
	poison := `upload_progress_vid|a:1:{s:4:"name";s:19:"<?php system('id');";}`
	if err := os.WriteFile(poisonPath, []byte(poison), 0o600); err != nil {
		t.Fatal(err)
	}

	if mitigated := guard.ScanOnce(); mitigated != 1 {
		t.Fatalf("expected only the poisoned session to be mitigated, got %d", mitigated)
	}
	if _, err := os.Stat(benignPath); err != nil {
		t.Fatalf("expected benign upload_progress session to remain intact: %v", err)
	}
	if _, err := os.Stat(poisonPath); !os.IsNotExist(err) {
		t.Fatalf("expected poisoned session to be deleted even when AllowBenignUploadProgress is true")
	}
}
