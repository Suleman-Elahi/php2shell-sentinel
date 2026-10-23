package firewall

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/intel"
)

// CommandRunner abstracts OS firewall command execution for unit testing.
type CommandRunner func(name string, args ...string) error

// Enforcer synchronizes quarantined attacker IPs from the behavioral Tracker
// into the host OS kernel firewall (`iptables`/`nftables` on Linux,
// Windows Filtering Platform via `netsh advfirewall` on Windows).
// This enables zero-touch out-of-band IP blocking even when the HTTP reverse proxy is not in-line.
type Enforcer struct {
	cfg     *config.Config
	tracker *intel.Tracker
	logger  *audit.Logger
	runner  CommandRunner
	mu      sync.Mutex
	applied map[string]time.Time
}

// NewEnforcer creates a cross-platform OS firewall quarantine enforcer.
func NewEnforcer(cfg *config.Config, tracker *intel.Tracker, logger *audit.Logger) *Enforcer {
	return &Enforcer{
		cfg:     cfg,
		tracker: tracker,
		logger:  logger,
		runner:  defaultCommandRunner,
		applied: make(map[string]time.Time, 64),
	}
}

// SetCommandRunner overrides the OS command runner (used in unit tests).
func (e *Enforcer) SetCommandRunner(r CommandRunner) {
	e.runner = r
}

// Run periodically reconciles active bans from `intel.Tracker` into the OS firewall
// and removes expired rules on shutdown or ban expiration.
func (e *Enforcer) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		e.SyncOnce()
		select {
		case <-ctx.Done():
			e.CleanupAll()
			return
		case <-ticker.C:
		}
	}
}

// SyncOnce reconciles the tracker's active bans with OS kernel firewall rules.
func (e *Enforcer) SyncOnce() int {
	if !e.cfg.FirewallBanEnabled || e.cfg.Mode != config.ModeBlock {
		return 0
	}

	now := time.Now().UTC()
	activeBans := e.tracker.ActiveBans(now)
	activeMap := make(map[string]intel.ClientState, len(activeBans))
	for _, b := range activeBans {
		if parsed := net.ParseIP(b.IP); parsed != nil && !parsed.IsLoopback() {
			activeMap[parsed.String()] = b
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	changes := 0

	// 1. Add new OS firewall rules for newly quarantined IPs
	for ip, st := range activeMap {
		if _, exists := e.applied[ip]; exists {
			continue
		}
		if err := e.blockIPOS(ip); err == nil {
			e.applied[ip] = st.BannedUntil
			changes++
			e.logger.Log(audit.Event{
				Timestamp: now,
				Severity:  audit.SeverityCritical,
				Component: "firewall",
				Action:    "os_firewall_drop",
				RuleID:    "P2S-FW-DROP",
				ClientIP:  ip,
				Message:   fmt.Sprintf("Inserted OS firewall DROP rule for quarantined IP %s (%s)", ip, st.BanReason),
				Mitigated: true,
			})
		}
	}

	// 2. Remove expired or manually unbanned IPs from the OS firewall
	for ip := range e.applied {
		if _, stillActive := activeMap[ip]; !stillActive {
			if err := e.unblockIPOS(ip); err == nil {
				delete(e.applied, ip)
				changes++
				e.logger.Info("firewall", "os_firewall_unban", "Removed expired OS firewall rule for IP "+ip, nil)
			}
		}
	}

	return changes
}

// CleanupAll removes all firewall rules inserted by this Sentinel session.
func (e *Enforcer) CleanupAll() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for ip := range e.applied {
		_ = e.unblockIPOS(ip)
		delete(e.applied, ip)
	}
}

func (e *Enforcer) blockIPOS(ip string) error {
	// Strict validation prevents any possibility of argument/command injection
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsLoopback() {
		return fmt.Errorf("refusing to block invalid or loopback IP %q", ip)
	}
	cleanIP := parsed.String()

	if runtime.GOOS == "windows" {
		ruleName := "PHP2ShellSentinel_Block_" + cleanIP
		return e.runner("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName, "dir=in", "action=block", "remoteip="+cleanIP)
	}

	// Linux: try iptables (-I INPUT -s <IP> -j DROP) if not already present
	if err := e.runner("iptables", "-C", "INPUT", "-s", cleanIP, "-j", "DROP"); err == nil {
		return nil // Already present
	}
	return e.runner("iptables", "-I", "INPUT", "1", "-s", cleanIP, "-j", "DROP")
}

func (e *Enforcer) unblockIPOS(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP %q", ip)
	}
	cleanIP := parsed.String()

	if runtime.GOOS == "windows" {
		ruleName := "PHP2ShellSentinel_Block_" + cleanIP
		return e.runner("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	}

	return e.runner("iptables", "-D", "INPUT", "-s", cleanIP, "-j", "DROP")
}

func defaultCommandRunner(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Run()
}
