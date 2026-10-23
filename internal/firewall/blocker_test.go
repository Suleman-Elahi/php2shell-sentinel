package firewall_test

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/firewall"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/intel"
)

func TestEnforcer_SyncsQuarantinedIPsToOSFirewall(t *testing.T) {
	cfg := config.Default()
	cfg.FirewallBanEnabled = true
	cfg.Mode = config.ModeBlock

	now := time.Now().UTC()
	tracker := intel.NewTracker(40, 80, 4, 100, 15*time.Minute, 1024)
	logger := audit.NewBufferLogger(io.Discard, "json")

	enforcer := firewall.NewEnforcer(cfg, tracker, logger)

	var executedCmds []string
	enforcer.SetCommandRunner(func(name string, args ...string) error {
		cmdLine := name + " " + strings.Join(args, " ")
		executedCmds = append(executedCmds, cmdLine)
		if strings.Contains(cmdLine, "-C INPUT") {
			// Simulate rule not yet present in iptables
			return errors.New("not present")
		}
		return nil
	})

	// 1. Trigger a critical php2shell ban for 203.0.113.200
	banned, _ := tracker.AddRisk("203.0.113.200", 120, "P2S-2026100", now)
	if !banned {
		t.Fatal("expected IP 203.0.113.200 to be banned")
	}

	// 2. SyncOnce should insert the OS firewall block rule
	if changes := enforcer.SyncOnce(); changes != 1 {
		t.Fatalf("expected 1 firewall rule change, got %d", changes)
	}

	// 3. Unban the IP and verify SyncOnce removes the OS firewall rule
	tracker.Unban("203.0.113.200")
	if changes := enforcer.SyncOnce(); changes != 1 {
		t.Fatalf("expected 1 firewall rule removal after unban, got %d", changes)
	}
}
