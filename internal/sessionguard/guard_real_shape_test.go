<<<<<<< HEAD
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

func TestSessionGuard_RealPHPUploadProgressShapeScrubbedInPlace(t *testing.T) {
	sessDir := t.TempDir()
	quarantineDir := t.TempDir()

	cfg := config.Default()
	cfg.SessionDirs = []string{sessDir}
	cfg.QuarantineDir = quarantineDir

	logger := audit.NewBufferLogger(io.Discard, "json")
	guard := sessionguard.NewGuard(cfg, logger)

	// Full PHP rfc1867 session.upload_progress nested array shape alongside real application session keys
	realPayload := `user_id|i:1001;csrf_token|s:16:"a1b2c3d4e5f60718";` +
		`upload_progress_job42|a:5:{s:10:"start_time";i:1761560000;s:14:"content_length";i:262144;s:15:"bytes_processed";i:65536;s:4:"done";b:0;s:5:"files";a:1:{i:0;a:7:{s:10:"field_name";s:6:"avatar";s:4:"name";s:11:"profile.png";s:8:"tmp_name";N;s:5:"error";i:0;s:4:"done";b:0;s:10:"start_time";i:1761560000;s:15:"bytes_processed";i:65536;}}}` +
		`authenticated|b:1;`

	path := filepath.Join(sessDir, "sess_real_shape")
	if err := os.WriteFile(path, []byte(realPayload), 0o600); err != nil {
		t.Fatal(err)
	}

	if mitigated := guard.ScanOnce(); mitigated != 1 {
		t.Fatalf("expected 1 session scrubbed in place, got %d", mitigated)
	}

	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected session file to remain on disk after in-place scrub: %v", err)
	}
	want := `user_id|i:1001;csrf_token|s:16:"a1b2c3d4e5f60718";authenticated|b:1;`
	if string(gotBytes) != want {
		t.Fatalf("scrubbed content = %q, want %q", string(gotBytes), want)
	}
}

func TestSessionGuard_MalformedUploadProgressFallsBackToFullQuarantine(t *testing.T) {
	sessDir := t.TempDir()
	quarantineDir := t.TempDir()

	cfg := config.Default()
	cfg.SessionDirs = []string{sessDir}
	cfg.QuarantineDir = quarantineDir

	logger := audit.NewBufferLogger(io.Discard, "json")
	guard := sessionguard.NewGuard(cfg, logger)

	// Attacker-crafted session where string length (s:999:) is deliberately mismatched
	// to confuse naive parsers; must fall back to full quarantine + deletion.
	malformed := `user_id|i:42;upload_progress_bad|a:1:{s:4:"name";s:999:"short";}role|s:5:"admin";`
	path := filepath.Join(sessDir, "sess_malformed_uprog")
	if err := os.WriteFile(path, []byte(malformed), 0o600); err != nil {
		t.Fatal(err)
	}

	if mitigated := guard.ScanOnce(); mitigated != 1 {
		t.Fatalf("expected 1 session mitigated via full quarantine fallback, got %d", mitigated)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected malformed upload_progress session file to be deleted, stat err = %v", err)
=======
package sessionguard

import (
	"bytes"
	"testing"
)

// Industry-realistic session payload: login/cart keys plus the exact shape PHP
// emits for session.upload_progress while an upload is in flight. The guard
// must strip only the tracking entry and keep the session usable.
func TestStripUploadProgressPreservesActiveSession(t *testing.T) {
	content := []byte("user_id|i:42;csrf|s:32:\"d41d8cd98f00b204e9800998ecf8427e\";" +
		"upload_progress_fid123|a:5:{s:10:\"start_time\";i:1730000000;s:14:\"content_length\";i:100;" +
		"s:15:\"bytes_processed\";i:50;s:4:\"done\";b:0;s:4:\"name\";s:6:\"secret\";}")
	cleaned, ok := stripUploadProgressEntries(content)
	if !ok {
		t.Fatalf("expected benign upload_progress entry to be strippable")
	}
	if bytes.Contains(cleaned, []byte("upload_progress_")) {
		t.Fatalf("upload_progress entry not removed: %q", string(cleaned))
	}
	for _, keep := range []string{"user_id|i:42;", "csrf|s:32:\"d41d8cd98f00b204e9800998ecf8427e\";"} {
		if !bytes.Contains(cleaned, []byte(keep)) {
			t.Fatalf("legitimate session key lost after scrub: missing %q in %q", keep, string(cleaned))
		}
	}
}

// Malformed serialization (wrong string lengths) must be refused so the guard
// falls back to full quarantine instead of rewriting unpredictable content.
func TestStripRefusesMalformedSerialization(t *testing.T) {
	bad := []byte("user_id|i:42;upload_progress_x|a:1:{s:4:\"name\";s:3:\"file\";}")
	if _, ok := stripUploadProgressEntries(bad); ok {
		t.Fatalf("expected malformed serialized upload_progress entry to be rejected")
>>>>>>> 3d4e1ec (Add test: guard_real_shape_test.go)
	}
}
