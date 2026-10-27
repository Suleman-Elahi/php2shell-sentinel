package procwatch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
)

// ProcInfo holds cross-platform process telemetry for a running OS process.
type ProcInfo struct {
	PID     int
	PPID    int
	Name    string
	Cmdline string
	RSSKB   uint64
}

// ProcessEnumerator abstracts OS process table listing for testability and cross-platform support.
type ProcessEnumerator func() ([]ProcInfo, error)

// ProcessKiller abstracts terminating a malicious process by PID.
type ProcessKiller func(pid int) error

// Watcher monitors the host process tree for PHP workers (`php-fpm`, `php-cgi`, `httpd`, `w3wp.exe`)
// spawning unauthorized shells or reconnaissance binaries (`sh`, `bash`, `cmd.exe`, `powershell.exe`, `nc`, `curl`),
// as well as runaway worker memory exhaustion.
type Watcher struct {
	cfg                   *config.Config
	logger                *audit.Logger
	enumerate             ProcessEnumerator
	kill                  ProcessKiller
	phpNames              map[string]struct{}
	blockNames            map[string]struct{}
	allowedParentPatterns []string
	allowedChildPatterns  []string
	mu                    sync.Mutex
	alertedPID            map[int]time.Time

	burstMu    sync.Mutex
	burstUntil time.Time
	burstCh    chan struct{}
}

// NewWatcher creates a cross-platform process tree and memory watchdog.
func NewWatcher(cfg *config.Config, logger *audit.Logger) *Watcher {
	phpSet := make(map[string]struct{}, len(cfg.PHPProcessNames))
	for _, n := range cfg.PHPProcessNames {
		phpSet[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
	}
	blockSet := make(map[string]struct{}, len(cfg.BlockedChildNames))
	for _, n := range cfg.BlockedChildNames {
		blockSet[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
	}
	parentPatterns := normalizePatterns(cfg.AllowedParentCmdlinePatterns)
	childPatterns := normalizePatterns(cfg.AllowedChildCmdlinePatterns)
	return &Watcher{
		cfg:                   cfg,
		logger:                logger,
		enumerate:             listProcessesOS,
		kill:                  defaultKillProcess,
		phpNames:              phpSet,
		blockNames:            blockSet,
		allowedParentPatterns: parentPatterns,
		allowedChildPatterns:  childPatterns,
		alertedPID:            make(map[int]time.Time, 64),
		burstCh:               make(chan struct{}, 1),
	}
}

func normalizePatterns(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if trimmed := strings.ToLower(strings.TrimSpace(p)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// SetEnumeratorAndKiller allows unit tests to inject a mock process table and killer.
func (w *Watcher) SetEnumeratorAndKiller(enum ProcessEnumerator, killer ProcessKiller) {
	w.enumerate = enum
	w.kill = killer
}

// Run polls the process tree at ProcPollInterval until ctx is cancelled.
// A WAF finding calls TriggerBurst, which temporarily switches to the much
// faster ProcBurstInterval so short-lived commands (for example
// system('id')) are far more likely to be observed before they exit.
func (w *Watcher) Run(ctx context.Context) {
	interval := w.cfg.ProcPollInterval
	if interval <= 0 {
		interval = 150 * time.Millisecond
	}

	for {
		w.ScanOnce()

		poll := interval
		w.burstMu.Lock()
		if !w.burstUntil.IsZero() && time.Now().Before(w.burstUntil) {
			poll = w.cfg.ProcBurstInterval
			if poll <= 0 {
				poll = 10 * time.Millisecond
			}
		}
		w.burstMu.Unlock()

		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-w.burstCh:
			// A suspicious request was detected; rescan immediately.
			timer.Stop()
		case <-timer.C:
		}
	}
}

// TriggerBurst enables high-frequency process sampling for ProcBurstWindow.
// It is safe to call from any goroutine and never blocks.
func (w *Watcher) TriggerBurst() {
	w.burstMu.Lock()
	w.burstUntil = time.Now().Add(w.cfg.ProcBurstWindow)
	if w.cfg.ProcBurstWindow <= 0 {
		w.burstUntil = time.Now().Add(5 * time.Second)
	}
	w.burstMu.Unlock()

	select {
	case w.burstCh <- struct{}{}:
	default:
	}
}

// ScanOnce inspects the current OS process snapshot and mitigates any malicious PHP child processes
// or runaway memory workers.
func (w *Watcher) ScanOnce() int {
	procs, err := w.enumerate()
	if err != nil || len(procs) == 0 {
		return 0
	}

	byPID := make(map[int]ProcInfo, len(procs))
	childrenByPPID := make(map[int][]ProcInfo, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
		if p.PID > 1 && p.PPID > 0 {
			childrenByPPID[p.PPID] = append(childrenByPPID[p.PPID], p)
		}
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now().UTC()
	interventions := 0
	selfPID := os.Getpid()

	for _, proc := range procs {
		if proc.PID <= 1 || proc.PID == selfPID {
			continue
		}

		// 1. Check if this process is a PHP worker exceeding MaxWorkerRSSMB
		if w.cfg.MaxWorkerRSSMB > 0 && w.isPHPWorker(proc) {
			maxKB := w.cfg.MaxWorkerRSSMB * 1024
			if proc.RSSKB > maxKB {
				if _, already := w.alertedPID[proc.PID]; !already {
					mitigated := false
					if w.cfg.Mode == config.ModeBlock {
						if err := w.kill(proc.PID); err == nil {
							mitigated = true
							w.logger.Metrics().ProcessesKilled.Add(1)
						}
					}
					w.alertedPID[proc.PID] = now
					interventions++
					w.logger.Log(audit.Event{
						Timestamp: now,
						Severity:  audit.SeverityHigh,
						Component: "proc-watchdog",
						Action:    "worker_oom_preempted",
						RuleID:    "P2S-PROC-RSS",
						CVE:       "CVE-2026-109618",
						Chain:     "Chain-D/E-Worker-OOM",
						PID:       proc.PID,
						Message:   fmt.Sprintf("PHP worker %s (PID %d) exceeded RSS ceiling (%d KB > %d KB)", proc.Name, proc.PID, proc.RSSKB, maxKB),
						Mitigated: mitigated,
						RiskScore: 80,
					})
				}
			}
		}

		// 2. Check if this process is a blocked shell/utility spawned by a PHP worker parent (or grandparent)
		if !w.isBlockedChild(proc.Name, proc.Cmdline) {
			continue
		}

		parent, hasParent := byPID[proc.PPID]
		if !hasParent {
			continue
		}

		phpAncestor := false
		ancestorProc := parent
		if w.isPHPWorker(parent) {
			phpAncestor = true
		} else if gp, hasGP := byPID[parent.PPID]; hasGP && w.isPHPWorker(gp) && !matchesAnyPattern(parent.Cmdline, w.allowedParentPatterns) {
			phpAncestor = true
			ancestorProc = gp
		}

		if !phpAncestor {
			continue
		}

		if lastAlert, seen := w.alertedPID[proc.PID]; seen && now.Sub(lastAlert) < 10*time.Second {
			continue
		}

		descendants := collectDescendants(proc.PID, childrenByPPID, selfPID)
		var killedDescendantPIDs []string

		mitigated := false
		if w.cfg.Mode == config.ModeBlock && w.cfg.KillSuspiciousExec {
			// Kill the shell/wrapper and its entire descendant subtree so chained
			// commands (e.g. `sh -c "echo ...; sleep 30"`) do not survive as orphans under init.
			for _, desc := range descendants {
				if matchesAnyPattern(desc.Cmdline, w.allowedChildPatterns) {
					continue
				}
				if err := w.kill(desc.PID); err == nil {
					w.logger.Metrics().ProcessesKilled.Add(1)
					killedDescendantPIDs = append(killedDescendantPIDs, fmt.Sprintf("%d", desc.PID))
				}
				w.alertedPID[desc.PID] = now
			}
			if err := w.kill(proc.PID); err == nil {
				mitigated = true
				w.logger.Metrics().ProcessesKilled.Add(1)
			}
		}

		w.alertedPID[proc.PID] = now
		interventions++

		meta := map[string]string{
			"parent_pid":  fmt.Sprintf("%d", ancestorProc.PID),
			"parent_name": ancestorProc.Name,
			"child_pid":   fmt.Sprintf("%d", proc.PID),
			"child_name":  proc.Name,
			"cmdline":     proc.Cmdline,
		}
		if len(killedDescendantPIDs) > 0 {
			meta["killed_descendant_pids"] = strings.Join(killedDescendantPIDs, ",")
		}

		w.logger.Log(audit.Event{
			Timestamp: now,
			Severity:  audit.SeverityCritical,
			Component: "proc-watchdog",
			Action:    "malicious_child_spawn",
			RuleID:    "P2S-PROC-EXEC",
			CVE:       "CVE-2026-109618/CVE-2026-109619",
			Chain:     "Post-Exploit-RCE",
			PID:       proc.PID,
			Message:   fmt.Sprintf("PHP worker %s (PID %d) spawned suspicious child %s (PID %d)", ancestorProc.Name, ancestorProc.PID, proc.Name, proc.PID),
			Metadata:  meta,
			Mitigated: mitigated,
			RiskScore: 100,
		})
	}

	// Clean up exited PIDs from alert cache
	for pid := range w.alertedPID {
		if _, alive := byPID[pid]; !alive {
			delete(w.alertedPID, pid)
		}
	}

	return interventions
}

func (w *Watcher) isPHPWorker(proc ProcInfo) bool {
	if matchesAnyPattern(proc.Cmdline, w.allowedParentPatterns) {
		return false
	}
	base := strings.ToLower(filepath.Base(strings.TrimSpace(proc.Name)))
	if _, ok := w.phpNames[base]; ok {
		return true
	}
	if strings.HasPrefix(base, "php-fpm") || strings.HasPrefix(base, "php-cgi") {
		return true
	}
	// Bare `php` / `php8.x` binaries are only treated as web workers when running
	// PHP's built-in HTTP server (`php -S host:port`), sparing CLI scripts, queue workers, and Composer.
	if base == "php" || base == "php.exe" ||
		strings.HasPrefix(base, "php5") || strings.HasPrefix(base, "php7") || strings.HasPrefix(base, "php8") {
		return isBuiltinWebServerCmdline(proc.Cmdline)
	}
	return false
}

func isBuiltinWebServerCmdline(cmdline string) bool {
	fields := strings.Fields(cmdline)
	for i, f := range fields {
		if f == "-S" && i+1 < len(fields) && strings.Contains(fields[i+1], ":") {
			return true
		}
		if strings.HasPrefix(f, "-S") && len(f) > 2 && strings.Contains(f[2:], ":") {
			return true
		}
	}
	return false
}

func (w *Watcher) isBlockedChild(name, cmdline string) bool {
	if matchesAnyPattern(cmdline, w.allowedChildPatterns) {
		return false
	}
	base := strings.ToLower(filepath.Base(strings.TrimSpace(name)))
	if _, ok := w.blockNames[base]; ok {
		return true
	}
	lowerCmd := strings.ToLower(cmdline)
	return strings.Contains(lowerCmd, "/dev/tcp/") ||
		strings.Contains(lowerCmd, "mkfifo") ||
		strings.Contains(lowerCmd, "base64 -d")
}

func matchesAnyPattern(cmdline string, patterns []string) bool {
	if len(patterns) == 0 || cmdline == "" {
		return false
	}
	lower := strings.ToLower(cmdline)
	for _, pat := range patterns {
		if pat != "" && strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func collectDescendants(rootPID int, childrenByPPID map[int][]ProcInfo, selfPID int) []ProcInfo {
	var out []ProcInfo
	visited := map[int]struct{}{rootPID: {}}
	queue := append([]ProcInfo(nil), childrenByPPID[rootPID]...)
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		if curr.PID <= 1 || curr.PID == selfPID {
			continue
		}
		if _, seen := visited[curr.PID]; seen {
			continue
		}
		visited[curr.PID] = struct{}{}
		out = append(out, curr)
		queue = append(queue, childrenByPPID[curr.PID]...)
	}
	return out
}

func defaultKillProcess(pid int) error {
	return killProcessOS(pid)
}
