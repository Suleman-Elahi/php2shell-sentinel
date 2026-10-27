package sessionguard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

// Only serialized objects/custom-serializable values are Chain C gadget markers.
// Plain serialized arrays (for example the legitimate `upload_progress_x|a:1:{...}`
// state PHP writes during uploads) must not be labelled as handler-mismatch gadgets.
var serializedGadgetInSessionRegex = regexp.MustCompile(`\|[OC]:\d+:`)

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
				if updatedInfo, statErr := os.Stat(fullPath); statErr == nil {
					g.seen[fullPath] = fileMeta{
						modTime: updatedInfo.ModTime(),
						size:    updatedInfo.Size(),
					}
				} else {
					delete(g.seen, fullPath)
				}
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
		// Sites that explicitly rely on native PHP session.upload_progress for benign
		// resumable/progress-bar uploads can opt in via allow_benign_upload_progress,
		// while still blocking PHP code tags (P2S-SESS-CODE), object gadgets (P2S-SESS-MISMATCH),
		// and session inflation (P2S-SESS-INFLATE).
		if g.cfg.AllowBenignUploadProgress {
			return false
		}
		if g.cfg.ScrubUploadProgressInPlace {
			if cleaned, ok := stripUploadProgressEntries(content); ok && len(bytes.TrimSpace(cleaned)) > 0 {
				g.scrubFileInPlace(
					path,
					info.Mode().Perm(),
					cleaned,
					"P2S-SESS-UPROG",
					"CVE-2026-109618/CVE-2026-109619",
					"Upload-Progress-Armed",
					"upload_progress state stripped in place from active PHP session file (preserving user session)",
				)
				return true
			}
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

func (g *Guard) scrubFileInPlace(path string, perm os.FileMode, cleaned []byte, ruleID, cve, chain, reason string) {
	mitigated := false
	if g.cfg.Mode == config.ModeBlock && g.cfg.DeletePoisonedSess {
		if g.cfg.QuarantineDir != "" {
			_ = os.MkdirAll(g.cfg.QuarantineDir, 0o700)
			qName := fmt.Sprintf("%s.%d.quarantine", filepath.Base(path), time.Now().UnixNano())
			qPath := filepath.Join(g.cfg.QuarantineDir, qName)
			copyForensicSample(path, qPath, 64*1024)
		}
		if perm == 0 {
			perm = 0o600
		}
		tmpPath := fmt.Sprintf("%s.sentinel-tmp.%d", path, time.Now().UnixNano())
		if err := os.WriteFile(tmpPath, cleaned, perm); err == nil {
			if err := os.Rename(tmpPath, path); err == nil {
				mitigated = true
				g.logger.Metrics().SessionsCleaned.Add(1)
			} else {
				_ = os.Remove(tmpPath)
			}
		}
	}

	g.logger.Log(audit.Event{
		Timestamp: time.Now().UTC(),
		Severity:  audit.SeverityCritical,
		Component: "session-guard",
		Action:    "session_upload_progress_scrubbed",
		RuleID:    ruleID,
		CVE:       cve,
		Chain:     chain,
		Path:      path,
		Message:   reason,
		Mitigated: mitigated,
		RiskScore: 100,
	})
}

// stripUploadProgressEntries removes `upload_progress_<id>|<serialized_value>` entries
// from a PHP session payload while keeping all other session variables intact.
func stripUploadProgressEntries(content []byte) ([]byte, bool) {
	marker := []byte("upload_progress_")
	if !bytes.Contains(content, marker) {
		return content, false
	}

	var out bytes.Buffer
	rest := content
	strippedAny := false

	for len(rest) > 0 {
		idx := bytes.Index(rest, marker)
		if idx < 0 {
			out.Write(rest)
			break
		}
		out.Write(rest[:idx])
		afterKey := rest[idx:]
		pipeIdx := bytes.IndexByte(afterKey, '|')
		if pipeIdx < 0 {
			return nil, false
		}
		valBytes := afterKey[pipeIdx+1:]
		consumed, ok := skipPHPSerializedValue(valBytes, 0)
		if !ok {
			return nil, false
		}
		strippedAny = true
		rest = valBytes[consumed:]
	}

	if !strippedAny || bytes.Contains(out.Bytes(), marker) {
		return nil, false
	}
	return out.Bytes(), true
}

func skipPHPSerializedValue(data []byte, depth int) (int, bool) {
	if len(data) < 2 || depth > 64 {
		return 0, false
	}
	switch data[0] {
	case 'N':
		if data[1] == ';' {
			return 2, true
		}
		return 0, false
	case 'b', 'i', 'd', 'r', 'R':
		if data[1] != ':' {
			return 0, false
		}
		semi := bytes.IndexByte(data[2:], ';')
		if semi < 0 {
			return 0, false
		}
		return 2 + semi + 1, true
	case 's':
		if data[1] != ':' {
			return 0, false
		}
		colon := bytes.IndexByte(data[2:], ':')
		if colon <= 0 {
			return 0, false
		}
		strLen, err := strconv.Atoi(string(data[2 : 2+colon]))
		if err != nil || strLen < 0 {
			return 0, false
		}
		quoteStart := 2 + colon + 1
		// Expect `"<strLen bytes>";`
		endPos := quoteStart + 1 + strLen + 2
		if endPos > len(data) || data[quoteStart] != '"' || data[quoteStart+1+strLen] != '"' || data[quoteStart+1+strLen+1] != ';' {
			return 0, false
		}
		return endPos, true
	case 'a':
		if data[1] != ':' {
			return 0, false
		}
		colon := bytes.IndexByte(data[2:], ':')
		if colon <= 0 {
			return 0, false
		}
		count, err := strconv.Atoi(string(data[2 : 2+colon]))
		if err != nil || count < 0 || count > 4096 {
			return 0, false
		}
		braceStart := 2 + colon + 1
		if braceStart >= len(data) || data[braceStart] != '{' {
			return 0, false
		}
		pos := braceStart + 1
		for i := 0; i < count*2; i++ {
			step, ok := skipPHPSerializedValue(data[pos:], depth+1)
			if !ok {
				return 0, false
			}
			pos += step
		}
		if pos >= len(data) || data[pos] != '}' {
			return 0, false
		}
		return pos + 1, true
	default:
		return 0, false
	}
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
