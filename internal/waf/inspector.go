package waf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
)

// Finding describes a detected php2shell or legacy PHP attack vector.
type Finding struct {
	RuleID    string
	CVE       string
	Chain     string
	Severity  string
	RiskScore int
	Message   string
	Metadata  map[string]string
}

var (
	// ErrStalledUpload is returned when a multipart upload intentionally stalls
	// between chunks (> MultipartChunkTimeout) to trigger the session.c rfc1867 UAF.
	ErrStalledUpload = errors.New("php2shell: stalled multipart upload aborted (UAF timing defense)")

	// ErrMidStreamPayload is returned when the streaming body scanner detects a
	// php2shell payload padded past the initial inspection window.
	ErrMidStreamPayload = errors.New("php2shell: malicious multipart payload detected mid-stream")

	// ErrBodyTooLarge is returned when the request body exceeds MaxBodyBytes.
	ErrBodyTooLarge = errors.New("php2shell: request body exceeds MaxBodyBytes safety limit")
)

var (
	// Matches serialized PHP objects/references inside multipart filenames (Chain C)
	serializedFilenameRegex = regexp.MustCompile(`(?i)(\|[OaCrR]:\d+:|[OaC]:\d+:"[^"]+"|\bR:\d+;)`)

	// Matches LFI session inclusion paths and PEAR RCE gadgets (Chain A & syrax Stage 4)
	lfiSessionRegex = regexp.MustCompile(`(?i)(/sess_[a-z0-9,-]+|/php/sessions?/sess_|/tmp/sessions?/sess_|pearcmd\.php|\+config-create\+)`)

	// Matches PHP-CGI argument injection (CVE-2024-4577)
	cgiArgInjectionRegex = regexp.MustCompile(`(?i)(?:^|[?&;\s])(?:-d|-c|-n|-s|-e|%2d[dcns]|%ad[dcns]|allow_url_include|allow_url_fopen|auto_prepend_file|auto_append_file)`)

	// Matches PHP OOM fatal error in response body
	phpOOMResponseRegex = regexp.MustCompile(`Allowed memory size of \d+ bytes exhausted`)
)

// Inspector performs deep, low-allocation inspection of HTTP requests and responses
// for all known CVE-2026-109618, CVE-2026-109619, and CVE-2024-4577 exploit chains.
type Inspector struct {
	cfg     *config.Config
	bufPool sync.Pool
}

// NewInspector creates a new WAF Inspector using a pooled buffer allocator.
func NewInspector(cfg *config.Config) *Inspector {
	windowSize := cfg.InspectWindowBytes
	if windowSize <= 0 {
		windowSize = 256 * 1024
	}
	return &Inspector{
		cfg: cfg,
		bufPool: sync.Pool{
			New: func() any {
				b := make([]byte, windowSize)
				return &b
			},
		},
	}
}

// IsMultipartRequest returns true if the request carries a multipart Content-Type
// (including comma variants like `multipart/form-data,boundary=x` parsed by PHP).
func IsMultipartRequest(r *http.Request) bool {
	for _, ct := range r.Header.Values("Content-Type") {
		if strings.Contains(strings.ToLower(ct), "multipart") {
			return true
		}
	}
	return false
}

// InspectRequest inspects the HTTP headers, URL, cookies, and body (with pooled pre-read
// plus continuous mid-stream scanning for large uploads).
func (ins *Inspector) InspectRequest(r *http.Request) (*Finding, error) {
	// 1. Check URL / Query for LFI session inclusion, PEAR gadgets, and CGI argument injection
	if f := ins.inspectURL(r.URL); f != nil {
		return f, nil
	}

	// 2. Check Header Count & Size Limits
	if len(r.Header) > 64 {
		return &Finding{
			RuleID:    "P2S-2026108-HDR",
			CVE:       "CVE-2026-109618",
			Chain:     "Heap-Spray",
			Severity:  "HIGH",
			RiskScore: 60,
			Message:   fmt.Sprintf("excessive HTTP header count (%d) blocked", len(r.Header)),
		}, nil
	}

	// 3. Check Cookies for forged binary pointers / heap-feng-shui session IDs
	if f := ins.inspectCookies(r); f != nil {
		return f, nil
	}

	// 4. Strip or flag PHP_SESSION_UPLOAD_PROGRESS header if sent as an HTTP header
	if r.Header.Get(ins.cfg.UploadProgressFieldName) != "" {
		if ins.cfg.StripUploadProgress {
			r.Header.Del(ins.cfg.UploadProgressFieldName)
		}
		return &Finding{
			RuleID:    "P2S-2026100-HDR",
			CVE:       "CVE-2026-109618/CVE-2026-109619",
			Chain:     "Chain-A/C/E",
			Severity:  "HIGH",
			RiskScore: 90,
			Message:   "PHP_SESSION_UPLOAD_PROGRESS header blocked",
		}, nil
	}

	isMP := IsMultipartRequest(r)

	// 5. Enforce AllowedUploadPaths if configured
	if isMP && len(ins.cfg.AllowedUploadPaths) > 0 {
		allowed := false
		for _, p := range ins.cfg.AllowedUploadPaths {
			if r.URL.Path == p {
				allowed = true
				break
			}
		}
		if !allowed {
			return &Finding{
				RuleID:    "P2S-2026110-PATH",
				CVE:       "CVE-2026-109618/CVE-2026-109619",
				Chain:     "Multipart-Policy",
				Severity:  "HIGH",
				RiskScore: 70,
				Message:   fmt.Sprintf("multipart upload to non-allowlisted path %q blocked", r.URL.Path),
			}, nil
		}
	}

	// 6. Rule P2S-2026105: Block chunked or missing Content-Length on multipart requests
	// PHP's rfc1867_post_handler skips post_max_size validation when content_length == 0.
	if isMP && ins.cfg.BlockChunkedMultipart {
		isChunked := len(r.TransferEncoding) > 0
		for _, te := range r.Header.Values("Transfer-Encoding") {
			if strings.Contains(strings.ToLower(te), "chunked") {
				isChunked = true
				break
			}
		}
		if isChunked || r.ContentLength < 0 {
			return &Finding{
				RuleID:    "P2S-2026105",
				CVE:       "CVE-2026-109618",
				Chain:     "Chain-D/ASLR-Bypass",
				Severity:  "HIGH",
				RiskScore: 85,
				Message:   "chunked or missing Content-Length multipart POST blocked (post_max_size OOM bypass)",
			}, nil
		}
	}

	// 7. Enforce hard Content-Length ceiling before reading body
	if r.ContentLength > ins.cfg.MaxBodyBytes {
		return &Finding{
			RuleID:    "P2S-2026105-SIZE",
			CVE:       "CVE-2026-109618",
			Chain:     "Chain-D",
			Severity:  "HIGH",
			RiskScore: 80,
			Message:   fmt.Sprintf("Content-Length (%d bytes) exceeds MaxBodyBytes (%d bytes)", r.ContentLength, ins.cfg.MaxBodyBytes),
		}, nil
	}

	// 8. Check empty multipart boundary probe used by php2shell-scanner (`boundary=` with empty value)
	if isMP {
		for _, ct := range r.Header.Values("Content-Type") {
			lowerCT := strings.ToLower(ct)
			if strings.HasSuffix(strings.TrimSpace(lowerCT), "boundary=") || strings.Contains(lowerCT, "boundary=;") {
				return &Finding{
					RuleID:    "P2S-2026107-SCAN",
					CVE:       "CVE-2026-109618/CVE-2026-109619",
					Chain:     "Scanner-Probe",
					Severity:  "HIGH",
					RiskScore: 85,
					Message:   "empty multipart boundary scanner probe blocked",
				}, nil
			}
		}
	}

	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return nil, nil
	}

	// 9. Read up to InspectWindowBytes from r.Body using a pooled buffer
	bufPtr := ins.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer ins.bufPool.Put(bufPtr)

	var (
		totalRead int
		eof       bool
	)
	for totalRead < len(buf) {
		n, err := r.Body.Read(buf[totalRead:])
		totalRead += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				eof = true
				break
			}
			return nil, err
		}
		// For multipart uploads, if the entire Content-Length is not yet read and the caller
		// only sent a partial chunk, we still inspect what arrived immediately and let the
		// streaming wrapper enforce inter-chunk stall timeouts on the rest.
		if isMP && r.ContentLength > 0 && int64(totalRead) >= r.ContentLength {
			eof = true
			break
		}
		if isMP && totalRead > 0 && r.ContentLength > int64(len(buf)) {
			// Keep reading up to InspectWindowBytes
			continue
		}
		if isMP && totalRead > 0 && int64(totalRead) < r.ContentLength {
			// Partial chunk arrived; inspect immediately so stalled 2-phase uploads are caught
			break
		}
	}

	window := make([]byte, totalRead)
	copy(window, buf[:totalRead])

	if isMP {
		if f := ins.inspectMultipartChunk(window, 0); f != nil {
			return f, nil
		}
	} else {
		if f := ins.inspectFormBody(window); f != nil {
			return f, nil
		}
	}

	// Reconstruct r.Body so downstream PHP receives the exact byte stream, guarded by
	// our mid-stream sliding-window inspector and UAF stall timeout detector.
	if eof {
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(window))
	} else {
		r.Body = newGuardedStreamReader(r.Body, window, ins, isMP)
	}

	return nil, nil
}

func (ins *Inspector) inspectURL(u *url.URL) *Finding {
	if u == nil {
		return nil
	}
	rawURI := u.RequestURI()
	decodedURI, err := url.QueryUnescape(rawURI)
	if err != nil {
		decodedURI = rawURI
	}

	// Check LFI session inclusion & pearcmd.php RCE
	if lfiSessionRegex.MatchString(rawURI) || lfiSessionRegex.MatchString(decodedURI) {
		return &Finding{
			RuleID:    "P2S-2026106",
			CVE:       "CVE-2026-109618",
			Chain:     "Chain-A-LFI",
			Severity:  "CRITICAL",
			RiskScore: 100,
			Message:   "session file LFI or PEAR gadget inclusion attempt blocked",
			Metadata:  map[string]string{"uri": rawURI},
		}
	}

	// Check CVE-2024-4577 PHP-CGI argument injection
	if u.RawQuery != "" && (cgiArgInjectionRegex.MatchString(u.RawQuery) || cgiArgInjectionRegex.MatchString(decodedURI)) {
		return &Finding{
			RuleID:    "P2S-20244577",
			CVE:       "CVE-2024-4577",
			Chain:     "CGI-Arg-Injection",
			Severity:  "CRITICAL",
			RiskScore: 100,
			Message:   "PHP-CGI argument injection attempt blocked in query string",
			Metadata:  map[string]string{"query": u.RawQuery},
		}
	}

	return nil
}

func (ins *Inspector) inspectCookies(r *http.Request) *Finding {
	for _, hdr := range r.Header.Values("Cookie") {
		idx := strings.Index(hdr, "PHPSESSID=")
		if idx < 0 {
			continue
		}
		val := hdr[idx+len("PHPSESSID="):]
		if semi := strings.IndexByte(val, ';'); semi >= 0 {
			val = val[:semi]
		}
		val = strings.TrimSpace(val)

		// Check length (blocks 30MB session cookie or forged 384B reference payload in B2)
		if len(val) > ins.cfg.MaxSessionIDCookieLen {
			return &Finding{
				RuleID:    "P2S-2026109-COOKIE",
				CVE:       "CVE-2026-109618/CVE-2026-109619",
				Chain:     "ASLR-Bypass-B2",
				Severity:  "HIGH",
				RiskScore: 95,
				Message:   fmt.Sprintf("anomalous PHPSESSID cookie length (%d bytes) blocked", len(val)),
			}
		}

		// PHP session IDs only permit [a-zA-Z0-9,-]; raw binary or URL-encoded null/heap bytes indicate exploit forgery
		for i := 0; i < len(val); i++ {
			c := val[i]
			valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == ','
			if !valid {
				return &Finding{
					RuleID:    "P2S-2026109-FORGE",
					CVE:       "CVE-2026-109618",
					Chain:     "ASLR-Bypass-B1/B2",
					Severity:  "CRITICAL",
					RiskScore: 100,
					Message:   "illegal characters or binary pointer forgery in PHPSESSID cookie blocked",
				}
			}
		}
	}
	return nil
}

func (ins *Inspector) inspectFormBody(body []byte) *Finding {
	if len(body) == 0 {
		return nil
	}
	s := string(body)
	if cgiArgInjectionRegex.MatchString(s) {
		return &Finding{
			RuleID:    "P2S-20244577-BODY",
			CVE:       "CVE-2024-4577",
			Chain:     "CGI-Arg-Injection",
			Severity:  "CRITICAL",
			RiskScore: 100,
			Message:   "PHP-CGI directive injection blocked in request body",
		}
	}
	// Check Chain B var_destroy UAF payload (deep unserialize with R:N back-references)
	if bytes.Contains(body, []byte("R:")) && bytes.Count(body, []byte("i:")) > 200 {
		return &Finding{
			RuleID:    "P2S-2026103-UAF",
			CVE:       "CVE-2026-109618",
			Chain:     "Chain-B-var_destroy",
			Severity:  "CRITICAL",
			RiskScore: 100,
			Message:   "PHP var_destroy unserialize UAF payload blocked",
		}
	}
	return nil
}

// inspectMultipartChunk inspects a slice of a multipart request body for all php2shell vectors.
func (ins *Inspector) inspectMultipartChunk(chunk []byte, priorParts int) *Finding {
	if len(chunk) == 0 {
		return nil
	}

	// 1. SID 2026100: Block PHP_SESSION_UPLOAD_PROGRESS (case-sensitive & case-insensitive check)
	progressField := []byte(ins.cfg.UploadProgressFieldName)
	if bytes.Contains(chunk, progressField) || containsFoldASCII(chunk, progressField) {
		return &Finding{
			RuleID:    "P2S-2026100",
			CVE:       "CVE-2026-109618/CVE-2026-109619",
			Chain:     "Chain-A/C/D/E",
			Severity:  "CRITICAL",
			RiskScore: 100,
			Message:   fmt.Sprintf("blocked %s in multipart body", ins.cfg.UploadProgressFieldName),
		}
	}

	// 2. SID 2026101: Block PHPSESSID as a multipart form field (Session Fixation primitive, PR #22113)
	if ins.cfg.BlockSessionFixation {
		if bytes.Contains(chunk, []byte(`name="PHPSESSID"`)) ||
			bytes.Contains(chunk, []byte(`name='PHPSESSID'`)) ||
			bytes.Contains(chunk, []byte(`name=PHPSESSID`)) {
			return &Finding{
				RuleID:    "P2S-2026101",
				CVE:       "CVE-2026-109618/CVE-2026-109619",
				Chain:     "Session-Fixation",
				Severity:  "HIGH",
				RiskScore: 90,
				Message:   "PHPSESSID in multipart POST body blocked (session fixation bypass of use_only_cookies)",
			}
		}
	}

	// 3. Scan all Content-Disposition headers in the chunk for:
	//    - Part count limits (Chain D 300+ parts, ASLR bypass 860 parts, 619 149x spray)
	//    - Nested array depth (scanner.py 62 nested keys `a[][a][a]...`, pwn_pure 64 nested keys)
	//    - Empty boundary scanner probes (`--\nContent-Disposition:name=a;filename=\n\n`)
	//    - Filename length (`> MaxFilenameLen`, blocking 231B zend_string bin spray & 10KB+ inflation)
	//    - PHP code in filename (`<?php`, `<?=`, Chain A)
	//    - Serialized objects in filename (`|O:`, `|C:`, Chain C handler mismatch)
	partCount := priorParts
	search := chunk
	cdToken := []byte("content-disposition:")

	for len(search) > 0 {
		idx := indexFoldASCII(search, cdToken)
		if idx < 0 {
			break
		}
		partCount++
		if partCount > ins.cfg.MaxMultipartParts {
			return &Finding{
				RuleID:    "P2S-2026108",
				CVE:       "CVE-2026-109618/CVE-2026-109619",
				Chain:     "Chain-D/Heap-Spray",
				Severity:  "HIGH",
				RiskScore: 90,
				Message:   fmt.Sprintf("multipart part count (%d) exceeds limit (%d)", partCount, ins.cfg.MaxMultipartParts),
			}
		}

		lineStart := idx + len(cdToken)
		rest := search[lineStart:]
		lineEnd := bytes.IndexByte(rest, '\n')
		var cdLine []byte
		if lineEnd >= 0 {
			cdLine = rest[:lineEnd]
			search = rest[lineEnd+1:]
		} else {
			cdLine = rest
			search = nil
		}

		// Check nested array brackets depth in field name (e.g. a[][a][a]...)
		openBrackets := bytes.Count(cdLine, []byte("["))
		if openBrackets > ins.cfg.MaxArrayDepth {
			return &Finding{
				RuleID:    "P2S-2026107-DEPTH",
				CVE:       "CVE-2026-109618",
				Chain:     "ASLR-Bypass/Scanner-Probe",
				Severity:  "HIGH",
				RiskScore: 95,
				Message:   fmt.Sprintf("deeply nested multipart field array (depth %d > %d) blocked", openBrackets, ins.cfg.MaxArrayDepth),
			}
		}

		// Check Assetnote/php2shell-scanner control probe (`Content-Disposition:name=a;filename=`)
		trimmedCD := bytes.TrimSpace(cdLine)
		if bytes.EqualFold(trimmedCD, []byte("name=a;filename=")) {
			return &Finding{
				RuleID:    "P2S-2026107-CTRL",
				CVE:       "CVE-2026-109618/CVE-2026-109619",
				Chain:     "Scanner-Probe",
				Severity:  "HIGH",
				RiskScore: 80,
				Message:   "php2shell scanner control probe signature blocked",
			}
		}

		// Inspect `filename=` parameter if present
		if fnIdx := indexFoldASCII(cdLine, []byte("filename=")); fnIdx >= 0 {
			fnVal := extractFilenameValue(cdLine[fnIdx+len("filename="):])

			// SID 2026104: Oversized filename (blocks 231B zend_string spray & >10KB session inflation)
			if len(fnVal) > ins.cfg.MaxFilenameLen {
				return &Finding{
					RuleID:    "P2S-2026104",
					CVE:       "CVE-2026-109618/CVE-2026-109619",
					Chain:     "Chain-E/ZendMM-Spray",
					Severity:  "HIGH",
					RiskScore: 85,
					Message:   fmt.Sprintf("oversized multipart filename (%d bytes > %d limit) blocked", len(fnVal), ins.cfg.MaxFilenameLen),
				}
			}

			// SID 2026102: PHP code in upload filename (Chain A session file poisoning)
			if bytes.Contains(fnVal, []byte("<?")) || containsFoldASCII(fnVal, []byte("<script")) {
				return &Finding{
					RuleID:    "P2S-2026102",
					CVE:       "CVE-2026-109618",
					Chain:     "Chain-A",
					Severity:  "CRITICAL",
					RiskScore: 100,
					Message:   "PHP code tag in multipart upload filename blocked (session poisoning)",
				}
			}

			// SID 2026103: Serialized PHP object in upload filename (Chain C handler mismatch)
			if serializedFilenameRegex.Match(fnVal) {
				return &Finding{
					RuleID:    "P2S-2026103",
					CVE:       "CVE-2026-109619",
					Chain:     "Chain-C",
					Severity:  "CRITICAL",
					RiskScore: 100,
					Message:   "serialized PHP object in multipart upload filename blocked (handler mismatch RCE)",
				}
			}
		}
	}

	return nil
}

// InspectResponse checks HTTP responses from the PHP backend for post-exploitation indicators:
//   - SID 2026112: Anomalous PHPSESSID in Set-Cookie (800KB heap / ASLR leak)
//   - SID 2026111: "Session object destruction failed" (CVE-2026-109619 stale BG exploitation)
//   - SID 2026110: "Allowed memory size of ... bytes exhausted" (CVE-2026-109618 OOM trigger)
//   - SID 2026116: X-Powered-By header scrubbing
func (ins *Inspector) InspectResponse(resp *http.Response, bodyPreview []byte) *Finding {
	if ins.cfg.StripPoweredBy {
		resp.Header.Del("X-Powered-By")
	}

	// 1. Check Set-Cookie headers for PHPSESSID heap memory leak (Sansec / poc_109618 / pwn_pure Stage B1)
	for _, sc := range resp.Header.Values("Set-Cookie") {
		idx := strings.Index(sc, "PHPSESSID=")
		if idx < 0 {
			continue
		}
		val := sc[idx+len("PHPSESSID="):]
		if semi := strings.IndexByte(val, ';'); semi >= 0 {
			val = val[:semi]
		}
		val = strings.TrimSpace(val)

		if len(val) > ins.cfg.MaxSessionIDCookieLen || containsEncodedBinaryLeak(val) {
			return &Finding{
				RuleID:    "P2S-2026112",
				CVE:       "CVE-2026-109618",
				Chain:     "ASLR-Heap-Leak",
				Severity:  "CRITICAL",
				RiskScore: 100,
				Message:   fmt.Sprintf("anomalous Set-Cookie PHPSESSID length (%d bytes) intercepted — heap/ASLR leak prevented", len(val)),
			}
		}
	}

	if len(bodyPreview) == 0 {
		return nil
	}

	// 2. Check for "Session object destruction failed" (CVE-2026-109619 Chain E)
	if bytes.Contains(bodyPreview, []byte("Session object destruction failed")) {
		return &Finding{
			RuleID:    "P2S-2026111",
			CVE:       "CVE-2026-109619",
			Chain:     "Chain-E-Stale-BG",
			Severity:  "CRITICAL",
			RiskScore: 100,
			Message:   "PHP 'Session object destruction failed' detected in response (stale BG state exploitation)",
		}
	}

	// 3. Check for PHP OOM fatal error in response (CVE-2026-109618 Chain D/E)
	if phpOOMResponseRegex.Match(bodyPreview) {
		chain := "Chain-D/E-OOM"
		score := 60
		if bytes.Contains(bodyPreview, []byte("in Unknown on line 0")) {
			// OOM occurred inside SAPI rfc1867 multipart parsing before any PHP script ran
			chain = "Chain-D-SAPI-OOM"
			score = 100
		}
		return &Finding{
			RuleID:    "P2S-2026110",
			CVE:       "CVE-2026-109618",
			Chain:     chain,
			Severity:  "HIGH",
			RiskScore: score,
			Message:   "PHP out-of-memory bailout detected in response body",
		}
	}

	return nil
}

// guardedStreamReader wraps an HTTP request body that was larger than InspectWindowBytes.
// It enforces:
//  1. MaxBodyBytes ceiling across the entire stream.
//  2. Inter-chunk stall timeout (defeats the >1s stall needed by CVE-2026-109618/109619 UAF).
//  3. Sliding-window inspection so attackers cannot pad 1MB of junk before PHP_SESSION_UPLOAD_PROGRESS.
type guardedStreamReader struct {
	underlying io.ReadCloser
	prefix     bytes.Reader
	ins        *Inspector
	isMP       bool
	totalBytes int64
	partCount  int
	lastRead   time.Time
	overlap    [256]byte
	overlapLen int
}

func newGuardedStreamReader(rc io.ReadCloser, initialWindow []byte, ins *Inspector, isMP bool) *guardedStreamReader {
	g := &guardedStreamReader{
		underlying: rc,
		ins:        ins,
		isMP:       isMP,
		totalBytes: int64(len(initialWindow)),
		lastRead:   time.Now(),
	}
	g.prefix.Reset(initialWindow)
	if isMP {
		g.partCount = bytes.Count(bytes.ToLower(initialWindow), []byte("content-disposition:"))
		if len(initialWindow) > len(g.overlap) {
			copy(g.overlap[:], initialWindow[len(initialWindow)-len(g.overlap):])
			g.overlapLen = len(g.overlap)
		} else {
			copy(g.overlap[:], initialWindow)
			g.overlapLen = len(initialWindow)
		}
	}
	return g
}

func (g *guardedStreamReader) Read(p []byte) (int, error) {
	if g.prefix.Len() > 0 {
		return g.prefix.Read(p)
	}

	startWait := time.Now()
	n, err := g.underlying.Read(p)
	now := time.Now()

	if g.isMP && g.ins.cfg.MultipartChunkTimeout > 0 {
		if now.Sub(startWait) > g.ins.cfg.MultipartChunkTimeout || now.Sub(g.lastRead) > g.ins.cfg.MultipartChunkTimeout {
			_ = g.underlying.Close()
			return 0, ErrStalledUpload
		}
	}
	g.lastRead = now

	if n > 0 {
		g.totalBytes += int64(n)
		if g.totalBytes > g.ins.cfg.MaxBodyBytes {
			_ = g.underlying.Close()
			return 0, ErrBodyTooLarge
		}

		if g.isMP {
			// Combine tail overlap from previous read with current chunk to catch boundary-spanning tokens
			scanBuf := make([]byte, g.overlapLen+n)
			copy(scanBuf, g.overlap[:g.overlapLen])
			copy(scanBuf[g.overlapLen:], p[:n])

			if f := g.ins.inspectMultipartChunk(scanBuf, g.partCount); f != nil {
				_ = g.underlying.Close()
				return 0, fmt.Errorf("%w: %s (%s)", ErrMidStreamPayload, f.RuleID, f.Message)
			}
			g.partCount += bytes.Count(bytes.ToLower(p[:n]), []byte("content-disposition:"))

			if len(scanBuf) > len(g.overlap) {
				copy(g.overlap[:], scanBuf[len(scanBuf)-len(g.overlap):])
				g.overlapLen = len(g.overlap)
			} else {
				copy(g.overlap[:], scanBuf)
				g.overlapLen = len(scanBuf)
			}
		}
	}

	return n, err
}

func (g *guardedStreamReader) Close() error {
	return g.underlying.Close()
}

func extractFilenameValue(raw []byte) []byte {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	if raw[0] == '"' || raw[0] == '\'' {
		quote := raw[0]
		rest := raw[1:]
		if end := bytes.IndexByte(rest, quote); end >= 0 {
			return rest[:end]
		}
		return rest
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] == ';' || raw[i] == '\r' || raw[i] == '\n' {
			return raw[:i]
		}
	}
	return raw
}

func containsEncodedBinaryLeak(val string) bool {
	// Heap leaks via Set-Cookie PHPSESSID contain URL-encoded null bytes (%00) or high pointers (%7f, %7e, etc.)
	lower := strings.ToLower(val)
	return strings.Contains(lower, "%00") ||
		strings.Contains(lower, "%7f") ||
		strings.Contains(lower, "%ff") ||
		strings.Contains(lower, "/")
}

func containsFoldASCII(haystack, needle []byte) bool {
	return indexFoldASCII(haystack, needle) >= 0
}

func indexFoldASCII(haystack, needle []byte) int {
	nLen := len(needle)
	if nLen == 0 {
		return 0
	}
	if len(haystack) < nLen {
		return -1
	}
	first := toLowerASCII(needle[0])
	limit := len(haystack) - nLen
	for i := 0; i <= limit; i++ {
		if toLowerASCII(haystack[i]) != first {
			continue
		}
		match := true
		for j := 1; j < nLen; j++ {
			if toLowerASCII(haystack[i+j]) != toLowerASCII(needle[j]) {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func toLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
