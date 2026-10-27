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

func TestWatcher_SparesQueueWorkersComposerAndCLIWhileProtectingBuiltinServer(t *testing.T) {
	cfg := config.Default()
	cfg.AllowedChildCmdlinePatterns = []string{"/usr/sbin/sendmail -t"}

	logger := audit.NewBufferLogger(io.Discard, "json")
	watcher := procwatch.NewWatcher(cfg, logger)

	var killedPIDs []int
	watcher.SetEnumeratorAndKiller(
		func() ([]procwatch.ProcInfo, error) {
			return []procwatch.ProcInfo{
				{PID: 1, PPID: 0, Name: "systemd", Cmdline: "/sbin/init"},
				// 1. Laravel queue worker spawning sh -> must NOT be killed
				{PID: 200, PPID: 1, Name: "php8.2", Cmdline: "php8.2 artisan queue:work --tries=3"},
				{PID: 201, PPID: 200, Name: "sh", Cmdline: "sh -c /usr/bin/ffmpeg -i in.mp4 out.mp4"},
				// 2. Composer install spawning curl -> must NOT be killed
				{PID: 300, PPID: 1, Name: "php", Cmdline: "php /usr/local/bin/composer install --no-dev"},
				{PID: 301, PPID: 300, Name: "curl", Cmdline: "curl -sS https://repo.packagist.org/packages.json"},
				// 3. Generic CLI deploy script spawning bash -> must NOT be killed
				{PID: 400, PPID: 1, Name: "php", Cmdline: "php deploy.php"},
				{PID: 401, PPID: 400, Name: "bash", Cmdline: "bash -c git pull"},
				// 4. PHP built-in web server (-S) spawning reverse shell -> MUST be killed
				{PID: 500, PPID: 1, Name: "php", Cmdline: "php -S 127.0.0.1:8081 -t public"},
				{PID: 501, PPID: 500, Name: "sh", Cmdline: "sh -c id"},
				// 5. php-fpm spawning allowlisted child command -> must NOT be killed
				{PID: 600, PPID: 1, Name: "php-fpm", Cmdline: "php-fpm: pool www"},
				{PID: 601, PPID: 600, Name: "sh", Cmdline: "sh -c /usr/sbin/sendmail -t"},
			}, nil
		},
		func(pid int) error {
			killedPIDs = append(killedPIDs, pid)
			return nil
		},
	)

	interventions := watcher.ScanOnce()
	if interventions != 1 {
		t.Fatalf("expected exactly 1 intervention (built-in web server shell PID 501), got %d (killed=%v)", interventions, killedPIDs)
	}
	if len(killedPIDs) != 1 || killedPIDs[0] != 501 {
		t.Fatalf("expected only PID 501 to be killed, got %v", killedPIDs)
	}
}

func TestWatcher_KillsEntireDescendantSubtreeOfWrappedShell(t *testing.T) {
	cfg := config.Default()

	logger := audit.NewBufferLogger(io.Discard, "json")
	watcher := procwatch.NewWatcher(cfg, logger)

	killedSet := make(map[int]bool)
	watcher.SetEnumeratorAndKiller(
		func() ([]procwatch.ProcInfo, error) {
			return []procwatch.ProcInfo{
				{PID: 1, PPID: 0, Name: "init", Cmdline: "/sbin/init"},
				{PID: 500, PPID: 1, Name: "apache2", Cmdline: "apache2 -DFOREGROUND"},
				// Wrapped shell chaining a persistent child (`sleep 30`) and grandchild
				{PID: 501, PPID: 500, Name: "sh", Cmdline: "sh -c echo pwned; sleep 30"},
				{PID: 502, PPID: 501, Name: "sleep", Cmdline: "sleep 30"},
				{PID: 503, PPID: 502, Name: "custom-implant", Cmdline: "/tmp/custom-implant --daemon"},
			}, nil
		},
		func(pid int) error {
			killedSet[pid] = true
			return nil
		},
	)

	interventions := watcher.ScanOnce()
	if interventions != 1 {
		t.Fatalf("expected 1 intervention for the shell tree, got %d", interventions)
	}
	for _, wantPID := range []int{501, 502, 503} {
		if !killedSet[wantPID] {
			t.Fatalf("expected PID %d in wrapped shell subtree to be killed, killedSet=%v", wantPID, killedSet)
		}
	}
}
