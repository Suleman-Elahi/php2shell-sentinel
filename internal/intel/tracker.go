package intel

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
)

var defaultLoopbackProxies, _ = config.ParseTrustedProxies([]string{"127.0.0.1/32", "::1/128"})

// ClientState tracks behavioral telemetry, token-bucket rate limiting,
// concurrent multipart streams (worker pinning defense), and risk score per IP.
type ClientState struct {
	IP                  string    `json:"ip"`
	Score               int       `json:"score"`
	BannedUntil         time.Time `json:"banned_until,omitempty"`
	BanReason           string    `json:"ban_reason,omitempty"`
	ActiveMultipart     int       `json:"active_multipart"`
	ProbesInWindow      int       `json:"probes_in_window"`
	OOMTriggers         int       `json:"oom_triggers"`
	LastSeen            time.Time `json:"last_seen"`
	FirstProbeInWindow  time.Time `json:"-"`
	tokens              float64
	lastTokenRefillTime time.Time
}

// Tracker is a bounded-memory, thread-safe behavioral threat intelligence engine.
// It detects multi-stage php2shell attacks:
//   - Reconnaissance bursts (small PHP_SESSION_UPLOAD_PROGRESS probes, SID 2026115)
//   - Apache prefork / PHP-FPM worker pinning (149 concurrent stalled multipart POSTs)
//   - Repeated OOM bailout probing (Chain D / E)
//   - Cumulative risk scoring and automatic quarantine (IP ban)
type Tracker struct {
	mu                sync.Mutex
	clients           map[string]*ClientState
	ratePerSec        float64
	burst             float64
	maxConcurrentMP   int
	banThresholdScore int
	banDuration       time.Duration
	maxTrackedIPs     int
	probeThreshold    int
	probeWindow       time.Duration
	trustedProxies    []*net.IPNet
	clientIPHeader    string
}

// NewTracker constructs a bounded behavioral threat intelligence tracker.
func NewTracker(ratePerSec float64, burst, maxConcurrentMP, banThresholdScore int, banDuration time.Duration, maxTrackedIPs int) *Tracker {
	if ratePerSec <= 0 {
		ratePerSec = 40
	}
	if burst <= 0 {
		burst = 80
	}
	if maxConcurrentMP <= 0 {
		maxConcurrentMP = 4
	}
	if banThresholdScore <= 0 {
		banThresholdScore = 100
	}
	if banDuration <= 0 {
		banDuration = 15 * time.Minute
	}
	if maxTrackedIPs <= 0 {
		maxTrackedIPs = 8192
	}
	return &Tracker{
		clients:           make(map[string]*ClientState, 256),
		ratePerSec:        ratePerSec,
		burst:             float64(burst),
		maxConcurrentMP:   maxConcurrentMP,
		banThresholdScore: banThresholdScore,
		banDuration:       banDuration,
		maxTrackedIPs:     maxTrackedIPs,
		probeThreshold:    3,
		probeWindow:       60 * time.Second,
		trustedProxies:    defaultLoopbackProxies,
		clientIPHeader:    "X-Forwarded-For",
	}
}

// SetTrustedProxies configures the CIDR ranges / IPs allowed to supply forwarded client IP headers
// (such as Nginx, Caddy, HAProxy, or Cloudflare in front of Sentinel) and the preferred header name.
func (t *Tracker) SetTrustedProxies(cidrs []string, clientIPHeader string) error {
	nets, err := config.ParseTrustedProxies(cidrs)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.trustedProxies = nets
	if strings.TrimSpace(clientIPHeader) != "" {
		t.clientIPHeader = strings.TrimSpace(clientIPHeader)
	}
	return nil
}

// SetProbeEscalation tunes the reconnaissance-probe escalation policy. A value
// <= 0 leaves the current setting unchanged. Raising the threshold or widening
// the window makes rule-by-rule scanner testing possible without disabling the
// auto-ban entirely.
func (t *Tracker) SetProbeEscalation(threshold int, window time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if threshold > 0 {
		t.probeThreshold = threshold
	}
	if window > 0 {
		t.probeWindow = window
	}
}

// ExtractClientIP resolves the real client IP using this tracker's configured trusted proxy ranges.
// Forwarded headers are only trusted when r.RemoteAddr belongs to a trusted proxy.
func (t *Tracker) ExtractClientIP(r *http.Request) string {
	t.mu.Lock()
	trusted := t.trustedProxies
	hdr := t.clientIPHeader
	t.mu.Unlock()
	return ExtractClientIPWithTrustedProxies(r, trusted, hdr)
}

// ExtractClientIP extracts the remote IP address from the HTTP request, trusting loopback
// proxies (127.0.0.1/32, ::1/128) by default for X-Forwarded-For / X-Real-IP headers.
func ExtractClientIP(r *http.Request) string {
	return ExtractClientIPWithTrustedProxies(r, defaultLoopbackProxies, "X-Forwarded-For")
}

// ExtractClientIPWithTrustedProxies extracts the client IP from r.
// If r.RemoteAddr is not in trustedProxies, forwarded headers are ignored to prevent spoofing.
// When r.RemoteAddr is a trusted proxy, X-Forwarded-For (or customHeader) is walked right-to-left
// to return the first non-trusted client IP, falling back to X-Real-IP.
func ExtractClientIPWithTrustedProxies(r *http.Request, trustedProxies []*net.IPNet, customHeader string) string {
	if r == nil {
		return ""
	}
	remoteIP := parseRemoteHost(r.RemoteAddr)
	if remoteIP == "" {
		return ""
	}

	if !isTrustedProxyIP(remoteIP, trustedProxies) {
		return remoteIP
	}

	// 1. Check custom client IP header if specified (e.g., CF-Connecting-IP, True-Client-IP, X-Real-IP)
	if customHeader != "" && !strings.EqualFold(customHeader, "X-Forwarded-For") {
		if ip := resolveForwardedChain(r.Header.Values(customHeader), trustedProxies); ip != "" {
			return ip
		}
	}

	// 2. Check X-Forwarded-For right-to-left (first untrusted hop from the right)
	if ip := resolveForwardedChain(r.Header.Values("X-Forwarded-For"), trustedProxies); ip != "" {
		return ip
	}

	// 3. Fallback to X-Real-IP
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if parsed := net.ParseIP(xri); parsed != nil {
			return parsed.String()
		}
	}

	return remoteIP
}

func parseRemoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		if parsed := net.ParseIP(host); parsed != nil {
			return parsed.String()
		}
		return host
	}
	trimmed := strings.TrimSpace(remoteAddr)
	if parsed := net.ParseIP(trimmed); parsed != nil {
		return parsed.String()
	}
	return trimmed
}

func isTrustedProxyIP(ipStr string, trusted []*net.IPNet) bool {
	if len(trusted) == 0 {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, netRange := range trusted {
		if netRange != nil && netRange.Contains(ip) {
			return true
		}
	}
	return false
}

func resolveForwardedChain(values []string, trusted []*net.IPNet) string {
	if len(values) == 0 {
		return ""
	}
	combined := strings.Join(values, ",")
	parts := strings.Split(combined, ",")
	var leftmostValid string
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if candidate == "" {
			continue
		}
		parsed := net.ParseIP(candidate)
		if parsed == nil {
			continue
		}
		canon := parsed.String()
		leftmostValid = canon
		if !isTrustedProxyIP(canon, trusted) {
			return canon
		}
	}
	return leftmostValid
}

// CheckAdmission verifies whether an IP is currently banned or exceeding the token-bucket rate limit.
// Returns (allowed, reason, banned).
func (t *Tracker) CheckAdmission(ip string, now time.Time) (bool, string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.getOrCreateLocked(ip, now)
	if !st.BannedUntil.IsZero() && now.Before(st.BannedUntil) {
		return false, "IP quarantined: " + st.BanReason, true
	}

	// Token bucket refill
	elapsed := now.Sub(st.lastTokenRefillTime).Seconds()
	if elapsed > 0 {
		st.tokens += elapsed * t.ratePerSec
		if st.tokens > t.burst {
			st.tokens = t.burst
		}
		st.lastTokenRefillTime = now
	}

	if st.tokens < 1.0 {
		st.Score += 10
		if st.Score >= t.banThresholdScore {
			st.BannedUntil = now.Add(t.banDuration)
			st.BanReason = "excessive request flood / rate limit violation"
		}
		return false, "rate limit exceeded", false
	}
	st.tokens -= 1.0
	st.LastSeen = now
	return true, "", false
}

// AcquireMultipartSlot tracks in-flight multipart requests per IP to defeat
// the 149-worker pinning technique used in php2shell ASLR-bypass exploits.
func (t *Tracker) AcquireMultipartSlot(ip string, now time.Time) (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.getOrCreateLocked(ip, now)
	if st.ActiveMultipart >= t.maxConcurrentMP {
		st.Score += 50
		if st.Score >= t.banThresholdScore {
			st.BannedUntil = now.Add(t.banDuration)
			st.BanReason = "worker pinning attack detected (excessive concurrent multipart uploads)"
		}
		return false, st.ActiveMultipart
	}
	st.ActiveMultipart++
	return true, st.ActiveMultipart
}

// ReleaseMultipartSlot decrements the active multipart counter for an IP.
func (t *Tracker) ReleaseMultipartSlot(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if st, ok := t.clients[ip]; ok {
		if st.ActiveMultipart > 0 {
			st.ActiveMultipart--
		}
	}
}

// AddRisk increments an IP's threat score and triggers an automatic ban if the threshold is crossed.
// Returns (newlyBanned, totalScore).
func (t *Tracker) AddRisk(ip string, points int, reason string, now time.Time) (bool, int) {
	if ip == "" {
		return false, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.getOrCreateLocked(ip, now)
	wasBanned := !st.BannedUntil.IsZero() && now.Before(st.BannedUntil)
	st.Score += points
	st.LastSeen = now

	// Track reconnaissance probe frequency (SID 2026115: 3 probes within 60s escalates immediately)
	if now.Sub(st.FirstProbeInWindow) > t.probeWindow {
		st.FirstProbeInWindow = now
		st.ProbesInWindow = 1
	} else {
		st.ProbesInWindow++
	}
	if st.ProbesInWindow >= t.probeThreshold && st.Score < t.banThresholdScore {
		st.Score = t.banThresholdScore
		reason = "repeated php2shell probing (" + reason + ")"
	}

	if st.Score >= t.banThresholdScore {
		st.BannedUntil = now.Add(t.banDuration)
		st.BanReason = reason
		return !wasBanned, st.Score
	}
	return false, st.Score
}

// RecordOOM records that a request from this IP triggered a PHP OOM or crash indicator.
func (t *Tracker) RecordOOM(ip string, now time.Time) (bool, int) {
	if ip == "" {
		return false, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.getOrCreateLocked(ip, now)
	st.OOMTriggers++
	return t.addRiskLocked(st, 60, "PHP OOM bailout / memory exhaustion trigger", now)
}

func (t *Tracker) addRiskLocked(st *ClientState, points int, reason string, now time.Time) (bool, int) {
	wasBanned := !st.BannedUntil.IsZero() && now.Before(st.BannedUntil)
	st.Score += points
	st.LastSeen = now
	if st.Score >= t.banThresholdScore {
		st.BannedUntil = now.Add(t.banDuration)
		st.BanReason = reason
		return !wasBanned, st.Score
	}
	return false, st.Score
}

// ActiveBans returns a snapshot of all currently banned clients.
func (t *Tracker) ActiveBans(now time.Time) []ClientState {
	t.mu.Lock()
	defer t.mu.Unlock()

	var out []ClientState
	for _, st := range t.clients {
		if !st.BannedUntil.IsZero() && now.Before(st.BannedUntil) {
			out = append(out, *st)
		}
	}
	return out
}

// Unban removes a quarantine ban for the specified IP.
func (t *Tracker) Unban(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	st, ok := t.clients[ip]
	if !ok {
		return false
	}
	st.BannedUntil = time.Time{}
	st.BanReason = ""
	st.Score = 0
	return true
}

func (t *Tracker) getOrCreateLocked(ip string, now time.Time) *ClientState {
	if st, ok := t.clients[ip]; ok {
		return st
	}
	// Evict expired or oldest entry if table is at capacity (prevents memory exhaustion under spoofed-IP DDoS)
	if len(t.clients) >= t.maxTrackedIPs {
		t.evictOneLocked(now)
	}
	st := &ClientState{
		IP:                  ip,
		LastSeen:            now,
		FirstProbeInWindow:  now,
		tokens:              t.burst,
		lastTokenRefillTime: now,
	}
	t.clients[ip] = st
	return st
}

func (t *Tracker) evictOneLocked(now time.Time) {
	var oldestKey string
	var oldestTime time.Time

	for k, v := range t.clients {
		// Prefer evicting non-banned idle entries
		if (v.BannedUntil.IsZero() || now.After(v.BannedUntil)) && v.ActiveMultipart == 0 {
			if oldestKey == "" || v.LastSeen.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.LastSeen
			}
		}
	}
	if oldestKey != "" {
		delete(t.clients, oldestKey)
		return
	}
	// Fallback: evict any single entry
	for k := range t.clients {
		delete(t.clients, k)
		return
	}
}
