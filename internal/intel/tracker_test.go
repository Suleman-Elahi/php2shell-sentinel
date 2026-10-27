package intel_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/intel"
)

func TestExtractClientIP_TrustedProxyAndSpoofResistance(t *testing.T) {
	tr := intel.NewTracker(50, 100, 2, 100, 10*time.Minute, 128)
	if err := tr.SetTrustedProxies([]string{"127.0.0.1/32", "10.0.0.0/8"}, "X-Forwarded-For"); err != nil {
		t.Fatalf("SetTrustedProxies failed: %v", err)
	}

	// 1. Untrusted direct peer spoofing X-Forwarded-For must be ignored
	reqSpoof := httptest.NewRequest("GET", "http://sentinel.local/index.php", nil)
	reqSpoof.RemoteAddr = "198.51.100.200:54321"
	reqSpoof.Header.Set("X-Forwarded-For", "1.1.1.1")
	reqSpoof.Header.Set("X-Real-IP", "1.1.1.1")
	if got := tr.ExtractClientIP(reqSpoof); got != "198.51.100.200" {
		t.Fatalf("expected untrusted peer IP 198.51.100.200 (ignoring spoofed XFF), got %q", got)
	}

	// 2. Trusted local Nginx proxy (127.0.0.1) passing real client IP via X-Forwarded-For
	// Client forged "8.8.8.8", Nginx appended "203.0.113.45". Right-to-left selection must pick 203.0.113.45.
	reqNginx := httptest.NewRequest("GET", "http://sentinel.local/index.php", nil)
	reqNginx.RemoteAddr = "127.0.0.1:41234"
	reqNginx.Header.Set("X-Forwarded-For", "8.8.8.8, 203.0.113.45, 10.0.1.9")
	if got := tr.ExtractClientIP(reqNginx); got != "203.0.113.45" {
		t.Fatalf("expected right-most untrusted client IP 203.0.113.45, got %q", got)
	}

	// 3. Trusted local Nginx proxy passing only X-Real-IP
	reqRealIP := httptest.NewRequest("GET", "http://sentinel.local/index.php", nil)
	reqRealIP.RemoteAddr = "127.0.0.1:41235"
	reqRealIP.Header.Set("X-Real-IP", "192.0.2.99")
	if got := tr.ExtractClientIP(reqRealIP); got != "192.0.2.99" {
		t.Fatalf("expected X-Real-IP 192.0.2.99 from trusted proxy, got %q", got)
	}
}

func TestTracker_ConfigurableProbeEscalation(t *testing.T) {
	now := time.Now().UTC()
	tr := intel.NewTracker(50, 100, 2, 100, 10*time.Minute, 128)
	tr.SetProbeEscalation(5, 5*time.Minute)

	ip := "198.51.100.77"
	for i := 0; i < 4; i++ {
		if banned, _ := tr.AddRisk(ip, 10, "P2S-2026107", now.Add(time.Duration(i)*30*time.Second)); banned {
			t.Fatalf("expected no ban before the configured 5-probe threshold (probe %d)", i+1)
		}
	}

	// The widened 5-minute window keeps all probes in one bucket even though
	// they are spread across 120 seconds.
	if banned, score := tr.AddRisk(ip, 10, "P2S-2026107", now.Add(120*time.Second)); !banned {
		t.Fatalf("expected 5th probe to escalate at the configured threshold (score=%d)", score)
	}
}

func TestTracker_DefaultProbeThresholdRemainsThree(t *testing.T) {
	now := time.Now().UTC()
	tr := intel.NewTracker(50, 100, 2, 100, 10*time.Minute, 128)

	ip := "198.51.100.78"
	tr.AddRisk(ip, 10, "P2S-2026107", now)
	tr.AddRisk(ip, 10, "P2S-2026107", now.Add(time.Second))
	if banned, _ := tr.AddRisk(ip, 10, "P2S-2026107", now.Add(2*time.Second)); !banned {
		t.Fatal("expected default 3-probe escalation to remain in effect")
	}
}

func TestTracker_WorkerPinningAndReconEscalation(t *testing.T) {
	now := time.Now().UTC()
	tr := intel.NewTracker(50, 100, 2, 100, 10*time.Minute, 128)

	// 1. Test concurrent multipart slot cap (defeats 149-connection worker pinning)
	if ok, _ := tr.AcquireMultipartSlot("198.51.100.1", now); !ok {
		t.Fatal("expected slot 1 to succeed")
	}
	if ok, _ := tr.AcquireMultipartSlot("198.51.100.1", now); !ok {
		t.Fatal("expected slot 2 to succeed")
	}
	if ok, _ := tr.AcquireMultipartSlot("198.51.100.1", now); ok {
		t.Fatal("expected slot 3 to be rejected (worker-pinning protection)")
	}
	tr.ReleaseMultipartSlot("198.51.100.1")
	if ok, _ := tr.AcquireMultipartSlot("198.51.100.1", now); !ok {
		t.Fatal("expected slot acquisition after release to succeed")
	}

	// 2. Test reconnaissance probe escalation (3 low-score probes within 60s -> auto-ban)
	ip := "198.51.100.50"
	if banned, _ := tr.AddRisk(ip, 25, "P2S-2026107", now); banned {
		t.Fatal("should not ban on 1st low-score probe")
	}
	if banned, _ := tr.AddRisk(ip, 25, "P2S-2026107", now.Add(2*time.Second)); banned {
		t.Fatal("should not ban on 2nd low-score probe")
	}
	banned, score := tr.AddRisk(ip, 25, "P2S-2026107", now.Add(4*time.Second))
	if !banned {
		t.Fatalf("expected 3rd recon probe within 60s to trigger automatic quarantine ban (score=%d)", score)
	}
}
