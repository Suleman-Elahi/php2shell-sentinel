package waf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/intel"
)

// ShieldProxy wraps an HTTP ReverseProxy with the php2shell Inspector and Behavioral Tracker.
type ShieldProxy struct {
	cfg         *config.Config
	inspector   *Inspector
	tracker     *intel.Tracker
	logger      *audit.Logger
	proxy       *httputil.ReverseProxy
	onSuspicion func()
}

// NewShieldProxy constructs a high-performance reverse proxy shield in front of a PHP backend.
func NewShieldProxy(cfg *config.Config, tracker *intel.Tracker, logger *audit.Logger) (*ShieldProxy, error) {
	targetURL, err := url.Parse(cfg.BackendURL)
	if err != nil {
		return nil, fmt.Errorf("invalid backend_url %q: %w", cfg.BackendURL, err)
	}

	ins := NewInspector(cfg)
	rp := httputil.NewSingleHostReverseProxy(targetURL)

	// Tune transport for high concurrency and low memory overhead
	rp.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	sp := &ShieldProxy{
		cfg:       cfg,
		inspector: ins,
		tracker:   tracker,
		logger:    logger,
		proxy:     rp,
	}

	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origDirector(req)
		req.Header.Set("X-Sentinel-Shield", "active")
	}

	rp.ModifyResponse = sp.modifyResponse
	rp.ErrorHandler = sp.handleProxyError

	return sp, nil
}

// SetSuspicionHook registers a callback invoked when the WAF detects a
// malicious request. It must be called before the proxy starts serving traffic.
func (sp *ShieldProxy) SetSuspicionHook(fn func()) {
	sp.onSuspicion = fn
}

// ServeHTTP intercepts every incoming HTTP request before it can reach PHP.
func (sp *ShieldProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sp.logger.Metrics().TotalRequests.Add(1)
	now := time.Now()
	clientIP := intel.ExtractClientIP(r)

	// 1. Check Behavioral Threat Intelligence admission (Active IP Ban / Token Bucket Rate Limit)
	allowed, reason, isBanned := sp.tracker.CheckAdmission(clientIP, now)
	if !allowed {
		sp.logger.Metrics().ActiveBans.Store(int64(len(sp.tracker.ActiveBans(now))))
		action := "rate_limited"
		status := http.StatusTooManyRequests
		if isBanned {
			action = "quarantine_drop"
			status = http.StatusForbidden
		}
		sp.logger.Log(audit.Event{
			Timestamp: now,
			Severity:  audit.SeverityWarn,
			Component: "waf",
			Action:    action,
			RuleID:    "P2S-INTEL-BAN",
			ClientIP:  clientIP,
			Method:    r.Method,
			Path:      r.URL.Path,
			Message:   reason,
			Mitigated: sp.cfg.Mode == config.ModeBlock,
		})
		if sp.cfg.Mode == config.ModeBlock {
			sp.logger.Metrics().BlockedRequests.Add(1)
			w.Header().Set("X-Blocked-By", "php2shell-sentinel")
			http.Error(w, "403 Forbidden - Blocked by PHP2Shell Sentinel", status)
			return
		}
	}

	// 2. Track concurrent multipart connections per IP (Defeats 149-worker pinning in ASLR bypass)
	isMP := IsMultipartRequest(r)
	if isMP {
		slotOK, activeCount := sp.tracker.AcquireMultipartSlot(clientIP, now)
		if !slotOK {
			sp.logger.Metrics().ActiveBans.Store(int64(len(sp.tracker.ActiveBans(now))))
			sp.logger.Log(audit.Event{
				Timestamp: now,
				Severity:  audit.SeverityCritical,
				Component: "waf",
				Action:    "worker_pinning_blocked",
				RuleID:    "P2S-2026108-PIN",
				CVE:       "CVE-2026-109618/CVE-2026-109619",
				Chain:     "ASLR-Worker-Pinning",
				ClientIP:  clientIP,
				Method:    r.Method,
				Path:      r.URL.Path,
				Message:   fmt.Sprintf("concurrent multipart limit exceeded (%d active streams) — worker pinning attack blocked", activeCount),
				Mitigated: sp.cfg.Mode == config.ModeBlock,
				RiskScore: 50,
			})
			if sp.cfg.Mode == config.ModeBlock {
				sp.logger.Metrics().BlockedRequests.Add(1)
				w.Header().Set("X-Blocked-By", "php2shell-sentinel")
				http.Error(w, "429 Too Many Concurrent Uploads - Worker Pinning Blocked", http.StatusTooManyRequests)
				return
			}
		} else {
			defer sp.tracker.ReleaseMultipartSlot(clientIP)
		}
	}

	if isMP && r.Body != nil {
		r.Body = newMultipartDeadlineBody(
			r.Body,
			requestReadDeadlineSetter(r, w),
			sp.cfg.MultipartChunkTimeout,
			time.Now().Add(sp.cfg.RequestReadTimeout),
		)
	}

	// 3. Deep Request Inspection (Headers, URL, Cookies, Pooled Multipart Window + Stream Guard)
	finding, err := sp.inspector.InspectRequest(r)
	if err != nil {
		sp.logger.Metrics().BlockedRequests.Add(1)
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}

	if finding != nil {
		newlyBanned, totalScore := sp.tracker.AddRisk(clientIP, finding.RiskScore, finding.RuleID+": "+finding.Message, now)
		if newlyBanned {
			sp.logger.Metrics().ActiveBans.Store(int64(len(sp.tracker.ActiveBans(now))))
		}

		mitigated := sp.cfg.Mode == config.ModeBlock
		action := "request_blocked"
		if !mitigated {
			action = "request_monitored"
			sp.logger.Metrics().MonitoredAlerts.Add(1)
		} else {
			sp.logger.Metrics().BlockedRequests.Add(1)
		}

		sp.logger.Log(audit.Event{
			Timestamp: now,
			Severity:  audit.Severity(finding.Severity),
			Component: "waf",
			Action:    action,
			RuleID:    finding.RuleID,
			CVE:       finding.CVE,
			Chain:     finding.Chain,
			ClientIP:  clientIP,
			Method:    r.Method,
			Path:      r.URL.Path,
			Message:   finding.Message,
			Metadata:  finding.Metadata,
			Mitigated: mitigated,
			RiskScore: totalScore,
		})

		// A malicious request may be the first stage of an exec chain. Ask the
		// process watchdog to sample the tree at high frequency for a short
		// window so short-lived children are not missed between normal polls.
		if sp.onSuspicion != nil {
			sp.onSuspicion()
		}

		if mitigated {
			w.Header().Set("X-Blocked-By", "php2shell-sentinel")
			w.Header().Set("X-Sentinel-Rule", finding.RuleID)
			http.Error(w, "403 Forbidden - Blocked by PHP2Shell Sentinel", http.StatusForbidden)
			return
		}
	}

	sp.logger.Metrics().AllowedRequests.Add(1)
	sp.proxy.ServeHTTP(w, r)
}

func (sp *ShieldProxy) modifyResponse(resp *http.Response) error {
	if !sp.cfg.InspectResponses {
		if sp.cfg.StripPoweredBy {
			resp.Header.Del("X-Powered-By")
		}
		return nil
	}

	// Read up to 64 KiB of the response body to check for PHP OOM / Session Destruction errors
	var preview []byte
	bodyComplete := false
	if resp.Body != nil {
		buf := make([]byte, 64*1024)
		n, err := io.ReadFull(resp.Body, buf)
		if n > 0 {
			preview = buf[:n]
		}
		bodyComplete = err == io.EOF || err == io.ErrUnexpectedEOF

		// Scrub common PHP version disclosures from small, uncompressed text
		// responses (for example pages that print PHP_VERSION directly).
		if bodyComplete && sp.cfg.ScrubPHPVersionInBody &&
			resp.Header.Get("Content-Encoding") == "" &&
			isTextResponse(resp.Header.Get("Content-Type")) {
			if scrubbed, changed := scrubPHPVersionFromBody(preview); changed {
				preview = scrubbed
				if resp.ContentLength >= 0 {
					resp.ContentLength = int64(len(preview))
					resp.Header.Set("Content-Length", strconv.Itoa(len(preview)))
				}
				sp.logVersionScrub(resp)
			}
		}

		if bodyComplete {
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(preview))
		} else if n > 0 {
			resp.Body = struct {
				io.Reader
				io.Closer
			}{
				Reader: io.MultiReader(bytes.NewReader(preview), resp.Body),
				Closer: resp.Body,
			}
		}
	}

	finding := sp.inspector.InspectResponse(resp, preview)
	if finding == nil {
		return nil
	}

	now := time.Now()
	clientIP := ""
	method := ""
	path := ""
	if resp.Request != nil {
		clientIP = intel.ExtractClientIP(resp.Request)
		method = resp.Request.Method
		if resp.Request.URL != nil {
			path = resp.Request.URL.Path
		}
	}

	newlyBanned, totalScore := sp.tracker.AddRisk(clientIP, finding.RiskScore, finding.RuleID+": "+finding.Message, now)
	if newlyBanned {
		sp.logger.Metrics().ActiveBans.Store(int64(len(sp.tracker.ActiveBans(now))))
	}
	sp.logger.Metrics().ResponsesScrubbed.Add(1)

	mitigated := sp.cfg.Mode == config.ModeBlock
	sp.logger.Log(audit.Event{
		Timestamp: now,
		Severity:  audit.Severity(finding.Severity),
		Component: "waf-response",
		Action:    "response_scrubbed",
		RuleID:    finding.RuleID,
		CVE:       finding.CVE,
		Chain:     finding.Chain,
		ClientIP:  clientIP,
		Method:    method,
		Path:      path,
		Message:   finding.Message,
		Mitigated: mitigated,
		RiskScore: totalScore,
	})

	if mitigated {
		// Strip leaked PHPSESSID cookie and replace body so attacker gets zero heap/ASLR leak or OOM signal
		resp.Header.Del("Set-Cookie")
		resp.Header.Set("X-Blocked-By", "php2shell-sentinel")
		resp.Header.Set("X-Sentinel-Rule", finding.RuleID)
		resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
		safeBody := []byte("403 Forbidden - Response Quarantined by PHP2Shell Sentinel\n")
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		resp.StatusCode = http.StatusForbidden
		resp.Status = "403 Forbidden"
		resp.Body = io.NopCloser(bytes.NewReader(safeBody))
		resp.ContentLength = int64(len(safeBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(safeBody)))
	}

	return nil
}

func isTextResponse(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml")
}

func (sp *ShieldProxy) logVersionScrub(resp *http.Response) {
	clientIP := ""
	method := ""
	path := ""
	if resp.Request != nil {
		clientIP = intel.ExtractClientIP(resp.Request)
		method = resp.Request.Method
		if resp.Request.URL != nil {
			path = resp.Request.URL.Path
		}
	}

	sp.logger.Metrics().ResponsesScrubbed.Add(1)
	sp.logger.Log(audit.Event{
		Severity:  audit.SeverityInfo,
		Component: "waf-response",
		Action:    "version_scrubbed",
		RuleID:    "P2S-2026116",
		ClientIP:  clientIP,
		Method:    method,
		Path:      path,
		Message:   "common PHP version string scrubbed from response body",
		Mitigated: sp.cfg.Mode == config.ModeBlock,
	})
}

func (sp *ShieldProxy) handleProxyError(w http.ResponseWriter, r *http.Request, err error) {
	now := time.Now()
	clientIP := intel.ExtractClientIP(r)

	// Check if our guardedStreamReader aborted an in-flight attack (stalled UAF upload or mid-stream payload)
	switch {
	case IsMultipartRequest(r) && isTimeoutError(err):
		sp.tracker.AddRisk(clientIP, 100, "multipart upload exceeded read deadline", now)
		sp.logger.Metrics().BlockedRequests.Add(1)
		sp.logger.Log(audit.Event{
			Timestamp: now,
			Severity:  audit.SeverityCritical,
			Component: "waf-stream",
			Action:    "stalled_upload_aborted",
			RuleID:    "P2S-2026100-STALL",
			CVE:       "CVE-2026-109618/CVE-2026-109619",
			Chain:     "UAF-Stall-Trigger",
			ClientIP:  clientIP,
			Method:    r.Method,
			Path:      r.URL.Path,
			Message:   err.Error(),
			Mitigated: true,
			RiskScore: 100,
		})
		w.Header().Set("X-Blocked-By", "php2shell-sentinel")
		w.Header().Set("X-Sentinel-Rule", "P2S-2026100-STALL")
		http.Error(w, "408 Request Timeout - Stalled Multipart Upload Aborted", http.StatusRequestTimeout)
		return

	case isErrorMatch(err, ErrStalledUpload):
		sp.tracker.AddRisk(clientIP, 100, "stalled multipart UAF timing attack", now)
		sp.logger.Metrics().BlockedRequests.Add(1)
		sp.logger.Log(audit.Event{
			Timestamp: now,
			Severity:  audit.SeverityCritical,
			Component: "waf-stream",
			Action:    "stalled_upload_aborted",
			RuleID:    "P2S-2026100-STALL",
			CVE:       "CVE-2026-109618/CVE-2026-109619",
			Chain:     "UAF-Stall-Trigger",
			ClientIP:  clientIP,
			Method:    r.Method,
			Path:      r.URL.Path,
			Message:   err.Error(),
			Mitigated: true,
			RiskScore: 100,
		})
		w.Header().Set("X-Blocked-By", "php2shell-sentinel")
		http.Error(w, "408 Request Timeout - Stalled Multipart Upload Aborted", http.StatusRequestTimeout)
		return

	case isErrorMatch(err, ErrMidStreamPayload):
		sp.tracker.AddRisk(clientIP, 100, err.Error(), now)
		sp.logger.Metrics().BlockedRequests.Add(1)
		sp.logger.Log(audit.Event{
			Timestamp: now,
			Severity:  audit.SeverityCritical,
			Component: "waf-stream",
			Action:    "midstream_payload_aborted",
			RuleID:    "P2S-2026100-STREAM",
			CVE:       "CVE-2026-109618/CVE-2026-109619",
			Chain:     "Padded-Multipart",
			ClientIP:  clientIP,
			Method:    r.Method,
			Path:      r.URL.Path,
			Message:   err.Error(),
			Mitigated: true,
			RiskScore: 100,
		})
		w.Header().Set("X-Blocked-By", "php2shell-sentinel")
		http.Error(w, "403 Forbidden - Mid-Stream Exploit Payload Aborted", http.StatusForbidden)
		return

	case isErrorMatch(err, ErrBodyTooLarge):
		sp.tracker.RecordOOM(clientIP, now)
		sp.logger.Metrics().BlockedRequests.Add(1)
		sp.logger.Log(audit.Event{
			Timestamp: now,
			Severity:  audit.SeverityHigh,
			Component: "waf-stream",
			Action:    "oversized_stream_aborted",
			RuleID:    "P2S-2026105-STREAM",
			CVE:       "CVE-2026-109618",
			Chain:     "Chain-D-OOM",
			ClientIP:  clientIP,
			Method:    r.Method,
			Path:      r.URL.Path,
			Message:   err.Error(),
			Mitigated: true,
			RiskScore: 80,
		})
		w.Header().Set("X-Blocked-By", "php2shell-sentinel")
		http.Error(w, "413 Payload Too Large", http.StatusRequestEntityTooLarge)
		return
	}

	sp.logger.Log(audit.Event{
		Timestamp: now,
		Severity:  audit.SeverityWarn,
		Component: "waf-proxy",
		Action:    "upstream_error",
		ClientIP:  clientIP,
		Method:    r.Method,
		Path:      r.URL.Path,
		Message:   fmt.Sprintf("upstream PHP backend error: %v", err),
		Mitigated: false,
	})
	http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
}

func isErrorMatch(err, target error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, target) || bytes.Contains([]byte(err.Error()), []byte(target.Error()))
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// multipartDeadlineBody enforces a deadline for every read from a multipart body.
// The overall request deadline remains in place between reads; the shorter
// MultipartChunkTimeout applies while waiting for the next network chunk.
type multipartDeadlineBody struct {
	body            io.ReadCloser
	setter          readDeadlineSetter
	chunkTimeout    time.Duration
	requestDeadline time.Time
}

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

type readDeadlineConnContextKey struct{}

// WithReadDeadlineConn makes a server connection available to the WAF request
// wrapper. The wrapper uses it to enforce individual multipart read deadlines.
func WithReadDeadlineConn(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, readDeadlineConnContextKey{}, conn)
}

func newMultipartDeadlineBody(
	body io.ReadCloser,
	setter readDeadlineSetter,
	chunkTimeout time.Duration,
	requestDeadline time.Time,
) *multipartDeadlineBody {
	return &multipartDeadlineBody{
		body:            body,
		setter:          setter,
		chunkTimeout:    chunkTimeout,
		requestDeadline: requestDeadline,
	}
}

func requestReadDeadlineSetter(r *http.Request, w http.ResponseWriter) readDeadlineSetter {
	if r != nil {
		if setter, ok := r.Context().Value(readDeadlineConnContextKey{}).(readDeadlineSetter); ok {
			return setter
		}
	}
	return http.NewResponseController(w)
}

func (b *multipartDeadlineBody) Read(p []byte) (int, error) {
	deadline := b.requestDeadline
	if b.chunkTimeout > 0 {
		chunkDeadline := time.Now().Add(b.chunkTimeout)
		if deadline.IsZero() || chunkDeadline.Before(deadline) {
			deadline = chunkDeadline
		}
	}
	b.setDeadline(deadline)

	n, err := b.body.Read(p)
	if isTimeoutError(err) {
		b.closeConnection()
	} else if errors.Is(err, io.EOF) {
		b.clearDeadline()
	} else {
		b.setDeadline(b.requestDeadline)
	}
	return n, err
}

func (b *multipartDeadlineBody) Close() error {
	b.clearDeadline()
	return b.body.Close()
}

func (b *multipartDeadlineBody) setDeadline(deadline time.Time) {
	if b.setter == nil {
		return
	}
	if err := b.setter.SetReadDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		// The server-wide request timeout remains active if the response writer
		// cannot apply a connection-specific deadline.
		return
	}
}

func (b *multipartDeadlineBody) clearDeadline() {
	b.setDeadline(time.Time{})
}

func (b *multipartDeadlineBody) closeConnection() {
	if conn, ok := b.setter.(interface{ Close() error }); ok {
		_ = conn.Close()
	}
}
