package waf_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/intel"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/waf"
)

func newTestShield(t *testing.T, backendHandler http.HandlerFunc) (*waf.ShieldProxy, *httptest.Server, *audit.Logger) {
	t.Helper()
	backend := httptest.NewServer(backendHandler)
	t.Cleanup(backend.Close)

	cfg := config.Default()
	cfg.BackendURL = backend.URL
	cfg.MultipartChunkTimeout = 120 * time.Millisecond
	cfg.InspectWindowBytes = 4096 // Small window to test both initial and mid-stream scanning

	logger := audit.NewBufferLogger(io.Discard, "json")
	tracker := intel.NewTracker(1000, 2000, 3, 100, 10*time.Minute, 1024)

	shield, err := waf.NewShieldProxy(cfg, tracker, logger)
	if err != nil {
		t.Fatalf("NewShieldProxy failed: %v", err)
	}
	return shield, backend, logger
}

func TestShieldProxy_BlocksAllPHP2ShellVectors(t *testing.T) {
	shield, _, logger := newTestShield(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})

	tests := []struct {
		name         string
		method       string
		path         string
		headers      map[string]string
		body         string
		chunked      bool
		wantStatus   int
		wantRulePref string
	}{
		{
			name:   "Legitimate GET request passes",
			method: http.MethodGet,
			path:   "/index.php?page=home",
			headers: map[string]string{
				"Cookie": "PHPSESSID=a043365f3b8b4cc6a5632fdefa8d1643",
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "Legitimate Multipart Upload passes",
			method: http.MethodPost,
			path:   "/upload.php",
			headers: map[string]string{
				"Content-Type": "multipart/form-data; boundary=---bound123",
			},
			body:       "-----bound123\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"photo.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nJPEGDATA\r\n-----bound123--\r\n",
			wantStatus: http.StatusOK,
		},
		{
			name:   "Legitimate upload filename containing a serialized array marker passes",
			method: http.MethodPost,
			path:   "/upload.php",
			headers: map[string]string{
				"Content-Type": "multipart/form-data; boundary=---b",
			},
			body:       "-----b\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"report|a:1:{s:1:\\\"x\\\";}.txt\"\r\n\r\nJPEGDATA\r\n-----b--\r\n",
			wantStatus: http.StatusOK,
		},
		{
			name:   "SID 2026100: Blocks PHP_SESSION_UPLOAD_PROGRESS in multipart POST",
			method: http.MethodPost,
			path:   "/index.php",
			headers: map[string]string{
				"Content-Type": "multipart/form-data; boundary=---b",
			},
			body:         "-----b\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\npwn\r\n-----b--\r\n",
			wantStatus:   http.StatusForbidden,
			wantRulePref: "P2S-2026100",
		},
		{
			name:   "SID 2026100: Blocks PHP_SESSION_UPLOAD_PROGRESS on PUT with comma Content-Type (PHP 8.4 bypass)",
			method: http.MethodPut,
			path:   "/index.php",
			headers: map[string]string{
				"Content-Type": "multipart/form-data,boundary=x",
			},
			body:         "--x\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n1\r\n--x--\r\n",
			wantStatus:   http.StatusForbidden,
			wantRulePref: "P2S-2026100",
		},
		{
			name:   "SID 2026101: Blocks PHPSESSID in multipart POST body (Session Fixation PR #22113)",
			method: http.MethodPost,
			path:   "/index.php",
			headers: map[string]string{
				"Content-Type": "multipart/form-data; boundary=---b",
			},
			body:         "-----b\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\nattacker_controlled_sid\r\n-----b--\r\n",
			wantStatus:   http.StatusForbidden,
			wantRulePref: "P2S-2026101",
		},
		{
			name:   "SID 2026102: Blocks Chain A PHP code in upload filename",
			method: http.MethodPost,
			path:   "/index.php",
			headers: map[string]string{
				"Content-Type": "multipart/form-data; boundary=---b",
			},
			body:         "-----b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"<?php system('id'); ?>.jpg\"\r\n\r\ndata\r\n-----b--\r\n",
			wantStatus:   http.StatusForbidden,
			wantRulePref: "P2S-2026102",
		},
		{
			name:   "SID 2026103: Blocks Chain C serialized object in upload filename (handler mismatch)",
			method: http.MethodPost,
			path:   "/index.php",
			headers: map[string]string{
				"Content-Type": "multipart/form-data; boundary=---b",
			},
			body:         "-----b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"|O:4:\\\"Evil\\\":1:{s:3:\\\"cmd\\\";s:2:\\\"id\\\";}\"\r\n\r\ndata\r\n-----b--\r\n",
			wantStatus:   http.StatusForbidden,
			wantRulePref: "P2S-2026103",
		},
		{
			name:   "SID 2026104: Blocks 231-byte ZendMM 256B bin spray filename",
			method: http.MethodPost,
			path:   "/index.php",
			headers: map[string]string{
				"Content-Type": "multipart/form-data; boundary=---b",
			},
			body:         "-----b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"" + strings.Repeat("A", 231) + "\"\r\n\r\ndata\r\n-----b--\r\n",
			wantStatus:   http.StatusForbidden,
			wantRulePref: "P2S-2026104",
		},
		{
			name:   "SID 2026105: Blocks Chunked Multipart POST (post_max_size OOM bypass)",
			method: http.MethodPost,
			path:   "/index.php",
			headers: map[string]string{
				"Content-Type":      "multipart/form-data; boundary=---b",
				"Transfer-Encoding": "chunked",
			},
			body:         "-----b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n-----b--\r\n",
			chunked:      true,
			wantStatus:   http.StatusForbidden,
			wantRulePref: "P2S-2026105",
		},
		{
			name:         "SID 2026106: Blocks Chain A LFI session file inclusion",
			method:       http.MethodGet,
			path:         "/index.php?page=../../../../var/lib/php/sessions/sess_pwn123",
			wantStatus:   http.StatusForbidden,
			wantRulePref: "P2S-2026106",
		},
		{
			name:         "SID 2026106: Blocks syrax Stage 4 pearcmd.php gadget",
			method:       http.MethodGet,
			path:         "/index.php?+config-create+/&file=/usr/share/php/pearcmd.php",
			wantStatus:   http.StatusForbidden,
			wantRulePref: "P2S-2026106",
		},
		{
			name:   "SID 2026107: Blocks 62-nested-key scanner/ASLR heap-shaping probe",
			method: http.MethodPost,
			path:   "/index.php",
			headers: map[string]string{
				"Content-Type": "multipart/form-data; boundary=x",
			},
			body:         "--x\r\nContent-Disposition: form-data; name=\"a[]" + strings.Repeat("[a]", 62) + "\"; filename=\"\"\r\n\r\n",
			wantStatus:   http.StatusForbidden,
			wantRulePref: "P2S-2026107",
		},
		{
			name:   "SID 2026109: Blocks forged binary/pointer PHPSESSID cookie (ASLR Stage B1/B2)",
			method: http.MethodPost,
			path:   "/index.php",
			headers: map[string]string{
				"Cookie": "PHPSESSID=fake_zend_string\x00\x7f\xe0\x0c\xc0",
			},
			body:         "a=1",
			wantStatus:   http.StatusForbidden,
			wantRulePref: "P2S-2026109",
		},
		{
			name:         "CVE-2024-4577: Blocks PHP-CGI argument injection",
			method:       http.MethodPost,
			path:         "/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
			body:         "<?php system('id'); ?>",
			wantStatus:   http.StatusForbidden,
			wantRulePref: "P2S-20244577",
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://sentinel.local"+tc.path, strings.NewReader(tc.body))
			// Use a distinct client IP per test case so auto-bans from one attack don't mask rule IDs of the next
			req.RemoteAddr = "10.0.0." + string(rune('1'+i)) + ":12345"
			req.RemoteAddr = "198.51.100." + strconvItoa(i+1) + ":54321"
			if tc.chunked {
				req.ContentLength = -1
				req.TransferEncoding = []string{"chunked"}
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			rec := httptest.NewRecorder()
			shield.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("got status %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantRulePref != "" {
				gotRule := rec.Header().Get("X-Sentinel-Rule")
				if !strings.HasPrefix(gotRule, tc.wantRulePref) {
					t.Errorf("got X-Sentinel-Rule %q, want prefix %q", gotRule, tc.wantRulePref)
				}
			}
		})
	}

	snap := logger.MetricsSnapshot()
	if snap.BlockedRequests == 0 {
		t.Errorf("expected BlockedRequests > 0, got 0")
	}
}

func TestShieldProxy_MidStreamPaddedPayloadBlocked(t *testing.T) {
	shield, _, _ := newTestShield(t, func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// Pad 32 KiB of benign multipart data (exceeding the 4 KiB test InspectWindowBytes)
	// followed by PHP_SESSION_UPLOAD_PROGRESS deep in the body.
	var body bytes.Buffer
	body.WriteString("-----b\r\nContent-Disposition: form-data; name=\"benign\"\r\n\r\n")
	body.WriteString(strings.Repeat("X", 32*1024))
	body.WriteString("\r\n-----b\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\npwn\r\n-----b--\r\n")

	req := httptest.NewRequest(http.MethodPost, "http://sentinel.local/index.php", &body)
	req.RemoteAddr = "203.0.113.77:40000"
	req.Header.Set("Content-Type", "multipart/form-data; boundary=---b")

	rec := httptest.NewRecorder()
	shield.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden && rec.Code != http.StatusBadRequest {
		t.Fatalf("expected mid-stream padded exploit to be aborted (403/400), got %d", rec.Code)
	}
}

func TestShieldProxy_ResponseGuardBlocksASLRHeapLeakAndOOM(t *testing.T) {
	t.Run("Blocks 800KB PHPSESSID Set-Cookie Heap/ASLR Leak (SID 2026112)", func(t *testing.T) {
		shield, _, _ := newTestShield(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Powered-By", "PHP/8.4.26")
			// Simulate Stage 1 / B1 uninitialized ZendMM chunk leak via Set-Cookie PHPSESSID
			leakedHeapCookie := "PHPSESSID=" + strings.Repeat("41424344", 32) + "%00%7f%e0%0c%60%00%00; path=/"
			w.Header().Add("Set-Cookie", leakedHeapCookie)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK\n"))
		})

		req := httptest.NewRequest(http.MethodGet, "http://sentinel.local/index.php", nil)
		req.RemoteAddr = "192.0.2.55:1111"
		rec := httptest.NewRecorder()
		shield.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 when response leaks heap memory in PHPSESSID cookie, got %d", rec.Code)
		}
		if sc := rec.Header().Get("Set-Cookie"); sc != "" {
			t.Fatalf("expected leaked Set-Cookie to be stripped, got %q", sc)
		}
		if xpb := rec.Header().Get("X-Powered-By"); xpb != "" {
			t.Fatalf("expected X-Powered-By to be stripped, got %q", xpb)
		}
	})

	t.Run("Blocks Session Object Destruction Failed Response (SID 2026111 Chain E)", func(t *testing.T) {
		shield, _, _ := newTestShield(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Warning: session_start(): Session object destruction failed in /var/www/html/index.php"))
		})

		req := httptest.NewRequest(http.MethodGet, "http://sentinel.local/index.php", nil)
		req.RemoteAddr = "192.0.2.56:1111"
		rec := httptest.NewRecorder()
		shield.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 on Session object destruction failed response, got %d", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "Session object destruction failed") {
			t.Fatalf("expected error output to be scrubbed from response body")
		}
	})
}

func BenchmarkInspector_LegitimateMultipart(b *testing.B) {
	cfg := config.Default()
	ins := waf.NewInspector(cfg)
	payload := []byte("-----bound123\r\nContent-Disposition: form-data; name=\"field\"; filename=\"report.pdf\"\r\nContent-Type: application/pdf\r\n\r\nPDFCONTENT1234567890\r\n-----bound123--\r\n")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest(http.MethodPost, "http://localhost/upload.php", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=---bound123")
		req.ContentLength = int64(len(payload))
		f, err := ins.InspectRequest(req)
		if err != nil || f != nil {
			b.Fatalf("unexpected block: f=%v err=%v", f, err)
		}
	}
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
