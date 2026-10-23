package logwatch_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/intel"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/logwatch"
)

func TestTailer_DetectsOOMAndStaleBGAndAutoBansAttackerIP(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "error.log")
	if err := os.WriteFile(logFile, []byte("initial benign line\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.WatchLogFiles = []string{logFile}

	logger := audit.NewBufferLogger(io.Discard, "json")
	tracker := intel.NewTracker(40, 80, 4, 100, 15*time.Minute, 1024)
	tailer := logwatch.NewTailer(cfg, tracker, logger)
	tailer.PrimeOffsets()

	// Append SAPI OOM error line with attacker IP and a Chain E stale BG error line
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("[Fri Oct 23 12:00:01 2026] [php:error] [pid 1234] [client 203.0.113.99:55112] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0\n")
	_, _ = f.WriteString("[Fri Oct 23 12:00:02 2026] [php:warn] [pid 1235] [client 203.0.113.100:55113] PHP Warning:  session_start(): Session object destruction failed in /var/www/html/index.php on line 2\n")
	_ = f.Close()

	alerts := tailer.PollOnce()
	if alerts != 2 {
		t.Fatalf("expected 2 log alerts, got %d", alerts)
	}

	bans := tracker.ActiveBans(time.Now().UTC())
	if len(bans) != 2 {
		t.Fatalf("expected both offending IPs (203.0.113.99 and 203.0.113.100) to be auto-banned, got %d bans", len(bans))
	}
}
