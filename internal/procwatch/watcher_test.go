package procwatch_test

import (
	"io"
	"testing"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/procwatch"
)

func TestWatcher_DetectsAndKillsMaliciousPHPChildProcesses(t *testing.T) {
	cfg := config.Default()
	cfg.MaxWorkerRSSMB = 128

	logger := audit.NewBufferLogger(io.Discard, "json")
	watcher := procwatch.NewWatcher(cfg, logger)

	var killedPIDs []int
	watcher.SetEnumeratorAndKiller(
		func() ([]procwatch.ProcInfo, error) {
			return []procwatch.ProcInfo{
				{PID: 100, PPID: 1, Name: "systemd", Cmdline: "/sbin/init", RSSKB: 4096},
				{PID: 500, PPID: 100, Name: "php-fpm8.4", Cmdline: "php-fpm: pool www", RSSKB: 32000},
				{PID: 501, PPID: 500, Name: "sh", Cmdline: "sh -c id > /out/p1", RSSKB: 1024},
				{PID: 600, PPID: 100, Name: "w3wp.exe", Cmdline: "w3wp.exe", RSSKB: 40000},
				{PID: 601, PPID: 600, Name: "powershell.exe", Cmdline: "powershell.exe -enc AAAA", RSSKB: 12000},
				{PID: 700, PPID: 100, Name: "apache2", Cmdline: "apache2 -k start", RSSKB: 256 * 1024}, // Exceeds 128MB RSS limit
			}, nil
		},
		func(pid int) error {
			killedPIDs = append(killedPIDs, pid)
			return nil
		},
	)

	interventions := watcher.ScanOnce()
	if interventions != 3 {
		t.Fatalf("expected 3 process watchdog interventions (sh, powershell.exe, runaway apache2 RSS), got %d", interventions)
	}
	if len(killedPIDs) != 3 {
		t.Fatalf("expected 3 killed PIDs, got %v", killedPIDs)
	}
}
