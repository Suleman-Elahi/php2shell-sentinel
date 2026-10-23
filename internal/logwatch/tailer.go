package logwatch

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/intel"
)

var (
	// Matches Apache / Nginx / PHP-FPM client IP formatting in error logs
	logClientIPRegex = regexp.MustCompile(`(?i)(?:\[client\s+([0-9a-fA-F.:]+)(?::\d+)?\]|client:\s*([0-9a-fA-F.:]+))`)
)

// Tailer incrementally monitors PHP and web server error logs for php2shell
// OOM bailouts, stale BG session destruction failures, and worker segfaults.
type Tailer struct {
	cfg     *config.Config
	tracker *intel.Tracker
	logger  *audit.Logger
	mu      sync.Mutex
	offsets map[string]int64
}

// NewTailer constructs an incremental log watcher.
func NewTailer(cfg *config.Config, tracker *intel.Tracker, logger *audit.Logger) *Tailer {
	return &Tailer{
		cfg:     cfg,
		tracker: tracker,
		logger:  logger,
		offsets: make(map[string]int64, len(cfg.WatchLogFiles)),
	}
}

// PrimeOffsets seeks to the current end of existing log files so historical entries are not re-alerted.
func (t *Tailer) PrimeOffsets() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, path := range t.cfg.WatchLogFiles {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			t.offsets[path] = info.Size()
		}
	}
}

// Run polls watched log files for newly appended lines (and optionally streams OS journal / Event Log) until ctx is cancelled.
func (t *Tailer) Run(ctx context.Context) {
	t.PrimeOffsets()

	var wg sync.WaitGroup
	if t.cfg.JournalWatchEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.runOSJournalStream(ctx)
		}()
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-ticker.C:
			t.PollOnce()
		}
	}
}

// runOSJournalStream reads directly from Linux `journalctl` or Windows Event Log (`wevtutil`)
// with zero application/file path configuration.
func (t *Tailer) runOSJournalStream(ctx context.Context) {
	if runtime.GOOS == "windows" {
		t.pollWindowsEventLog(ctx)
		return
	}

	// Linux: stream systemd journal if journalctl is available
	if _, err := exec.LookPath("journalctl"); err != nil {
		return
	}
	cmd := exec.CommandContext(ctx, "journalctl", "-f", "-n", "0", "-o", "cat")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		t.inspectLine("systemd-journal", scanner.Text())
	}
	_ = cmd.Wait()
}

func (t *Tailer) pollWindowsEventLog(ctx context.Context) {
	if _, err := exec.LookPath("wevtutil"); err != nil {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastSeen string
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			out, err := exec.CommandContext(ctx, "wevtutil", "qe", "Application", "/c:5", "/rd:true", "/f:text").Output()
			if err != nil || len(out) == 0 {
				continue
			}
			text := string(out)
			if text == lastSeen {
				continue
			}
			lastSeen = text
			scanner := bufio.NewScanner(strings.NewReader(text))
			for scanner.Scan() {
				t.inspectLine("windows-event-log", scanner.Text())
			}
		}
	}
}

// PollOnce reads newly appended lines from all configured log files and returns the number of alerts triggered.
func (t *Tailer) PollOnce() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	alerts := 0
	for _, path := range t.cfg.WatchLogFiles {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}

		offset := t.offsets[path]
		if info.Size() < offset {
			// Log file was rotated/truncated
			offset = 0
		}
		if info.Size() == offset {
			continue
		}

		f, err := os.Open(path)
		if err != nil {
			continue
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			continue
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if t.inspectLine(path, line) {
				alerts++
			}
		}
		newPos, err := f.Seek(0, io.SeekCurrent)
		if err == nil {
			t.offsets[path] = newPos
		} else {
			t.offsets[path] = info.Size()
		}
		_ = f.Close()
	}
	return alerts
}

func (t *Tailer) inspectLine(logPath, line string) bool {
	if line == "" {
		return false
	}

	var (
		ruleID    string
		cve       string
		chain     string
		severity  audit.Severity
		riskScore int
		msg       string
	)

	switch {
	case strings.Contains(line, "Allowed memory size of") && strings.Contains(line, "exhausted"):
		ruleID = "P2S-LOG-OOM"
		cve = "CVE-2026-109618"
		chain = "Chain-D/E-OOM"
		severity = audit.SeverityHigh
		riskScore = 60
		msg = "PHP out-of-memory error detected in log"
		if strings.Contains(line, "in Unknown on line 0") {
			ruleID = "P2S-LOG-SAPI-OOM"
			chain = "Chain-D-SAPI-OOM"
			severity = audit.SeverityCritical
			riskScore = 100
			msg = "SAPI-stage PHP multipart OOM ('in Unknown on line 0') detected in log"
		}

	case strings.Contains(line, "Session object destruction failed"):
		ruleID = "P2S-LOG-STALE-BG"
		cve = "CVE-2026-109619"
		chain = "Chain-E-Stale-BG"
		severity = audit.SeverityCritical
		riskScore = 100
		msg = "PHP 'Session object destruction failed' detected in log (stale BG exploitation)"

	case strings.Contains(line, "SIGSEGV") ||
		strings.Contains(line, "Segmentation fault") ||
		strings.Contains(line, "exit signal 11"):
		ruleID = "P2S-LOG-SEGV"
		cve = "CVE-2026-109618/CVE-2026-109619"
		chain = "UAF-Crash-Probe"
		severity = audit.SeverityHigh
		riskScore = 70
		msg = "PHP worker segmentation fault (SIGSEGV) detected in log"

	default:
		return false
	}

	now := time.Now().UTC()
	clientIP := extractIPFromLogLine(line)
	mitigated := false

	if clientIP != "" && t.tracker != nil {
		banned, totalScore := t.tracker.AddRisk(clientIP, riskScore, ruleID+": "+msg, now)
		riskScore = totalScore
		if banned {
			mitigated = true
			t.logger.Metrics().ActiveBans.Store(int64(len(t.tracker.ActiveBans(now))))
		}
	}

	t.logger.Metrics().LogAlerts.Add(1)
	t.logger.Log(audit.Event{
		Timestamp: now,
		Severity:  severity,
		Component: "log-watcher",
		Action:    "log_signature_match",
		RuleID:    ruleID,
		CVE:       cve,
		Chain:     chain,
		ClientIP:  clientIP,
		Path:      logPath,
		Message:   msg,
		Metadata: map[string]string{
			"log_excerpt": line,
		},
		Mitigated: mitigated,
		RiskScore: riskScore,
	})

	return true
}

func extractIPFromLogLine(line string) string {
	matches := logClientIPRegex.FindStringSubmatch(line)
	if len(matches) >= 2 && matches[1] != "" {
		return matches[1]
	}
	if len(matches) >= 3 && matches[2] != "" {
		return matches[2]
	}
	return ""
}
