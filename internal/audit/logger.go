package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Severity represents the criticality of an operational or security event.
type Severity string

const (
	SeverityDebug    Severity = "DEBUG"
	SeverityInfo     Severity = "INFO"
	SeverityWarn     Severity = "WARN"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Event represents a single structured security or operational log entry.
type Event struct {
	Timestamp  time.Time         `json:"timestamp"`
	Severity   Severity          `json:"severity"`
	Component  string            `json:"component"`
	Action     string            `json:"action"`
	RuleID     string            `json:"rule_id,omitempty"`
	CVE        string            `json:"cve,omitempty"`
	Chain      string            `json:"chain,omitempty"`
	ClientIP   string            `json:"client_ip,omitempty"`
	Method     string            `json:"method,omitempty"`
	Path       string            `json:"path,omitempty"`
	PID        int               `json:"pid,omitempty"`
	Message    string            `json:"message"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Mitigated  bool              `json:"mitigated"`
	RiskScore  int               `json:"risk_score,omitempty"`
}

// Metrics tracks low-overhead atomic counters for all agent operations.
type Metrics struct {
	TotalRequests     atomic.Uint64
	AllowedRequests   atomic.Uint64
	BlockedRequests   atomic.Uint64
	MonitoredAlerts   atomic.Uint64
	SanitizedRequests atomic.Uint64
	ResponsesScrubbed atomic.Uint64
	SessionsCleaned   atomic.Uint64
	ProcessesKilled   atomic.Uint64
	LogAlerts         atomic.Uint64
	ActiveBans        atomic.Int64
}

// Snapshot is a serializable point-in-time view of Metrics.
type Snapshot struct {
	TotalRequests     uint64 `json:"total_requests"`
	AllowedRequests   uint64 `json:"allowed_requests"`
	BlockedRequests   uint64 `json:"blocked_requests"`
	MonitoredAlerts   uint64 `json:"monitored_alerts"`
	SanitizedRequests uint64 `json:"sanitized_requests"`
	ResponsesScrubbed uint64 `json:"responses_scrubbed"`
	SessionsCleaned   uint64 `json:"sessions_cleaned"`
	ProcessesKilled   uint64 `json:"processes_killed"`
	LogAlerts         uint64 `json:"log_alerts"`
	ActiveBans        int64  `json:"active_bans"`
}

// Logger provides thread-safe, low-allocation structured logging and a fixed-size
// in-memory ring buffer of recent security events for live inspection.
type Logger struct {
	mu       sync.Mutex
	out      io.Writer
	file     *os.File
	format   string
	minLevel int
	ring     []Event
	ringHead int
	ringFull bool
	metrics  Metrics
}

const defaultRingCapacity = 256

// NewLogger creates a Logger writing to stderr and optionally to a log file.
func NewLogger(logFilePath, format, level string) (*Logger, error) {
	l := &Logger{
		out:      os.Stderr,
		format:   strings.ToLower(strings.TrimSpace(format)),
		minLevel: parseLevel(level),
		ring:     make([]Event, defaultRingCapacity),
	}
	if l.format == "" {
		l.format = "json"
	}
	if logFilePath != "" {
		if err := os.MkdirAll(filepath.Dir(logFilePath), 0o750); err != nil {
			return nil, fmt.Errorf("create log dir: %w", err)
		}
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, fmt.Errorf("open log file %q: %w", logFilePath, err)
		}
		l.file = f
		l.out = io.MultiWriter(os.Stderr, f)
	}
	return l, nil
}

// NewBufferLogger creates an in-memory logger for testing.
func NewBufferLogger(w io.Writer, format string) *Logger {
	if w == nil {
		w = io.Discard
	}
	return &Logger{
		out:      w,
		format:   format,
		minLevel: parseLevel("debug"),
		ring:     make([]Event, defaultRingCapacity),
	}
}

// Close closes any underlying log file handle.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

// Metrics returns the atomic metrics struct for direct counter updates.
func (l *Logger) Metrics() *Metrics {
	return &l.metrics
}

// MetricsSnapshot returns a point-in-time copy of all operational counters.
func (l *Logger) MetricsSnapshot() Snapshot {
	return Snapshot{
		TotalRequests:     l.metrics.TotalRequests.Load(),
		AllowedRequests:   l.metrics.AllowedRequests.Load(),
		BlockedRequests:   l.metrics.BlockedRequests.Load(),
		MonitoredAlerts:   l.metrics.MonitoredAlerts.Load(),
		SanitizedRequests: l.metrics.SanitizedRequests.Load(),
		ResponsesScrubbed: l.metrics.ResponsesScrubbed.Load(),
		SessionsCleaned:   l.metrics.SessionsCleaned.Load(),
		ProcessesKilled:   l.metrics.ProcessesKilled.Load(),
		LogAlerts:         l.metrics.LogAlerts.Load(),
		ActiveBans:        l.metrics.ActiveBans.Load(),
	}
}

// Log records an Event, sanitizing untrusted fields against log/terminal injection.
func (l *Logger) Log(ev Event) {
	if severityRank(ev.Severity) < l.minLevel {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	ev.Message = SanitizeLogString(ev.Message)
	ev.Path = SanitizeLogString(ev.Path)
	ev.ClientIP = SanitizeLogString(ev.ClientIP)
	if len(ev.Metadata) > 0 {
		cleanMeta := make(map[string]string, len(ev.Metadata))
		for k, v := range ev.Metadata {
			cleanMeta[SanitizeLogString(k)] = SanitizeLogString(v)
		}
		ev.Metadata = cleanMeta
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Store in ring buffer for security events (WARN and above) or operational actions
	if severityRank(ev.Severity) >= severityRank(SeverityInfo) {
		l.ring[l.ringHead] = ev
		l.ringHead = (l.ringHead + 1) % len(l.ring)
		if l.ringHead == 0 {
			l.ringFull = true
		}
	}

	if l.format == "text" {
		_, _ = fmt.Fprintf(l.out, "%s [%s] component=%s action=%s rule=%s ip=%s path=%q mitigated=%v msg=%q\n",
			ev.Timestamp.Format(time.RFC3339),
			ev.Severity,
			ev.Component,
			ev.Action,
			ev.RuleID,
			ev.ClientIP,
			ev.Path,
			ev.Mitigated,
			ev.Message,
		)
		return
	}

	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	data = append(data, '\n')
	_, _ = l.out.Write(data)
}

// Info logs a standard operational message.
func (l *Logger) Info(component, action, message string, meta map[string]string) {
	l.Log(Event{
		Severity:  SeverityInfo,
		Component: component,
		Action:    action,
		Message:   message,
		Metadata:  meta,
	})
}

// RecentEvents returns up to `limit` most recent events in chronological order.
func (l *Logger) RecentEvents(limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	var total int
	if l.ringFull {
		total = len(l.ring)
	} else {
		total = l.ringHead
	}
	if total == 0 {
		return nil
	}
	if limit <= 0 || limit > total {
		limit = total
	}

	out := make([]Event, 0, limit)
	start := (l.ringHead - limit + len(l.ring)) % len(l.ring)
	for i := 0; i < limit; i++ {
		idx := (start + i) % len(l.ring)
		out = append(out, l.ring[idx])
	}
	return out
}

// SanitizeLogString strips control characters (including ANSI escape sequences and newlines)
// to prevent log injection and terminal escape sequence attacks from attacker-controlled payloads.
func SanitizeLogString(s string) string {
	if s == "" {
		return ""
	}
	const maxLen = 512
	if len(s) > maxLen {
		s = s[:maxLen] + "...[truncated]"
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
		} else if c == '\t' {
			b.WriteByte(' ')
		} else {
			_, _ = fmt.Fprintf(&b, "\\x%02x", c)
		}
	}
	return b.String()
}

func parseLevel(lvl string) int {
	switch strings.ToUpper(strings.TrimSpace(lvl)) {
	case "DEBUG":
		return 0
	case "INFO", "":
		return 1
	case "WARN", "WARNING":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL", "ERROR":
		return 4
	default:
		return 1
	}
}

func severityRank(s Severity) int {
	switch s {
	case SeverityDebug:
		return 0
	case SeverityInfo:
		return 1
	case SeverityWarn:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 1
	}
}
