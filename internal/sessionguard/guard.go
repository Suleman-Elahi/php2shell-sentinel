package sessionguard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
)

type fileMeta struct {
	modTime time.Time
	size    int64
}

var serializedGadgetInSessionRegex = regexp.MustCompile(`\|[OaCr]:\d+:`)

// Guard watches PHP session directories for CVE-2026-109618 / CVE-2026-109619
// session poisoning (Chain A), handler mismatch payloads (Chain C), upload_progress
// state arming, and 30MB session inflation (Chain E).
type Guard struct {
	cfg    *config.Config
	logger *audit.Logger
	mu     sync.Mutex
	seen   map[string]fileMeta
}

// NewGuard creates a new PHP session directory guard.
func NewGuard(cfg *config.Config, logger *audit.Logger) *Guard {
	return &Guard{
		cfg:    cfg,
		logger: logger,
		seen:   make(map[string]fileMeta, 256),
	}
}

// Run starts the background session directory watcher until ctx is cancelled.
func (g *Guard) Run(ctx context.Context) {
	interval := g.cfg.SessionPollInterval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		g.ScanOnce()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// ScanOnce performs a single incremental pass across all configured PHP session directories.
// Only newly created or modified `sess_*` files are read.
func (g *Guard) ScanOnce() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	activeFiles := make(map[string]struct{}, len(g.seen))
	mitigatedCount := 0

	for _, dir := range g.cfg.SessionDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasPrefix(name, "sess_") {
				continue
			}
			fullPath := filepath.Join(dir, name)
			info, err := entry.Info()
			if err != nil {
				continue
			}
			// Never follow symlinks in session directories (prevents symlink planting attacks)
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}

			activeFiles[fullPath] = struct{}{}
			prev, ok := g.seen[fullPath]
			if ok && prev.modTime.Equal(info.ModTime()) && prev.size == info.Size() {
				continue
			}

			if g.inspectSessionFile(fullPath, info) {
				mitigatedCount++
				delete(g.seen, fullPath)
			} else {
				g.seen[fullPath] = fileMeta{
					modTime: info.ModTime(),
					size:    info.Size(),
				}
			}
		}
	}

	// Prune deleted session files from cache to keep memory flat
	for k := range g.seen {
		if _, exists := activeFiles[k]; !exists {
			delete(g.seen, k)
		}
	}

	return mitigatedCount
}

func (g *Guard) inspectSessionFile(path string, info os.FileInfo) bool {
	// 1. Check Chain E Session Inflation (attacker builds a multi-MB session file to OOM session_start)
	if g.cfg.MaxSessionFileBytes > 0 && info.Size() > g.cfg.MaxSessionFileBytes {
		g.mitigateFile(
			path,
			"P2S-SESS-INFLATE",
			"CVE-2026-109619",
			"Chain-E-Session-Inflation",
			fmt.Sprintf("oversized PHP session file (%d bytes > %d max) neutralized before OOM unserialize", info.Size(), g.cfg.MaxSessionFileBytes),
		)
		return true
	}

	// Read up to 128 KiB of the session file
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	buf := make([]byte, 128*1024)
	n, _ := io.ReadFull(f, buf)
	_ = f.Close()
	if n == 0 {
		return false
	}
	content := buf[:n]

	// 2. Check for injected PHP code in session file (Chain A LFI RCE)
	if bytes.Contains(content, []byte("<?php")) ||
		bytes.Contains(content, []byte("<?=")) ||
		bytes.Contains(content, []byte("system(")) ||
		bytes.Contains(content, []byte("passthru(")) ||
		bytes.Contains(content, []byte("shell_exec(")) {
		g.mitigateFile(
			path,
			"P2S-SESS-CODE",
			"CVE-2026-109618",
			"Chain-A-Session-Poison",
			"injected PHP code detected inside session file",
		)
		return true
	}

	// 3. Check for upload_progress_ tracking state in session file
	if bytes.Contains(content, []byte("upload_progress_")) {
		// Check if combined with Chain C handler mismatch (`|O:...`)
		if serializedGadgetInSessionRegex.Match(content) {
			g.mitigateFile(
				path,
				"P2S-SESS-MISMATCH",
				"CVE-2026-109619",
				"Chain-C-Handler-Mismatch",
				"upload_progress session containing serialized object gadget neutralized",
			)
			return true
		}
		g.mitigateFile(
			path,
			"P2S-SESS-UPROG",
			"CVE-2026-109618/CVE-2026-109619",
			"Upload-Progress-Armed",
			"unauthorized upload_progress state in PHP session file neutralized",
		)
		return true
	}

	return false
}

func (g *Guard) mitigateFile(path, ruleID, cve, chain, reason string) {
	mitigated := false
	if g.cfg.Mode == config.ModeBlock && g.cfg.DeletePoisonedSess {
		// Optionally quarantine a small forensic copy before unlinking
		if g.cfg.QuarantineDir != "" {
			_ = os.MkdirAll(g.cfg.QuarantineDir, 0o700)
			qName := fmt.Sprintf("%s.%d.quarantine", filepath.Base(path), time.Now().UnixNano())
			qPath := filepath.Join(g.cfg.QuarantineDir, qName)
			copyForensicSample(path, qPath, 64*1024)
		}
		if err := os.Remove(path); err == nil {
			mitigated = true
			g.logger.Metrics().SessionsCleaned.Add(1)
		}
	}

	g.logger.Log(audit.Event{
		Timestamp: time.Now().UTC(),
		Severity:  audit.SeverityCritical,
		Component: "session-guard",
		Action:    "session_poison_detected",
		RuleID:    ruleID,
		CVE:       cve,
		Chain:     chain,
		Path:      path,
		Message:   reason,
		Mitigated: mitigated,
		RiskScore: 100,
	})
}

func copyForensicSample(src, dst string, maxBytes int64) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	defer out.Close()

	_, _ = io.CopyN(out, in, maxBytes)
}
