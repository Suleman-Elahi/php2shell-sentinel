package agent

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/firewall"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/hardener"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/intel"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/logwatch"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/procwatch"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/sessionguard"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/waf"
)

// StatusReport is the JSON payload returned by the local `/status` control endpoint.
type StatusReport struct {
	Agent         string              `json:"agent"`
	OS            string              `json:"os"`
	Arch          string              `json:"arch"`
	Mode          config.Mode         `json:"mode"`
	UptimeSeconds int64               `json:"uptime_seconds"`
	Goroutines    int                 `json:"goroutines"`
	HeapAllocKB   uint64              `json:"heap_alloc_kb"`
	SysMemKB      uint64              `json:"sys_mem_kb"`
	Metrics       audit.Snapshot      `json:"metrics"`
	ActiveBans    []intel.ClientState `json:"active_bans"`
	RecentEvents  []audit.Event       `json:"recent_events"`
}

// Agent coordinates all defense layers of the PHP2Shell Sentinel.
type Agent struct {
	cfg          *config.Config
	logger       *audit.Logger
	tracker      *intel.Tracker
	proxy        *waf.ShieldProxy
	sessionGuard *sessionguard.Guard
	procWatcher  *procwatch.Watcher
	logTailer    *logwatch.Tailer
	fwEnforcer   *firewall.Enforcer
	startedAt    time.Time
}

// New constructs a new PHP2Shell Sentinel Agent.
func New(cfg *config.Config, logger *audit.Logger) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	tracker := intel.NewTracker(
		cfg.RateLimitPerSecond,
		cfg.RateLimitBurst,
		cfg.MaxConcurrentMultipart,
		cfg.BanThresholdScore,
		cfg.BanDuration,
		cfg.MaxTrackedIPs,
	)

	var shield *waf.ShieldProxy
	if cfg.ProxyEnabled {
		var err error
		shield, err = waf.NewShieldProxy(cfg, tracker, logger)
		if err != nil {
			return nil, err
		}
	}

	return &Agent{
		cfg:          cfg,
		logger:       logger,
		tracker:      tracker,
		proxy:        shield,
		sessionGuard: sessionguard.NewGuard(cfg, logger),
		procWatcher:  procwatch.NewWatcher(cfg, logger),
		logTailer:    logwatch.NewTailer(cfg, tracker, logger),
		fwEnforcer:   firewall.NewEnforcer(cfg, tracker, logger),
		startedAt:    time.Now().UTC(),
	}, nil
}

// Run starts all enabled sentinel subsystems and blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.startedAt = time.Now().UTC()

	a.logger.Info("agent", "startup", "PHP2Shell Sentinel starting", map[string]string{
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"mode":        string(a.cfg.Mode),
		"listen_addr": a.cfg.ListenAddr,
		"backend_url": a.cfg.BackendURL,
		"status_addr": a.cfg.StatusAddr,
	})

	if a.cfg.AutoHardenOnStart {
		a.runStartupHardening()
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// 1. Start Session Directory Guard
	if a.cfg.SessionGuardEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.logger.Info("session-guard", "started", "Monitoring PHP session directories", nil)
			a.sessionGuard.Run(ctx)
		}()
	}

	// 2. Start Process Tree & Memory Watchdog
	if a.cfg.ProcWatchEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.logger.Info("proc-watchdog", "started", "Monitoring PHP worker processes and child executions", nil)
			a.procWatcher.Run(ctx)
		}()
	}

	// 3. Start Log & OS Journal Tailer
	if a.cfg.LogWatchEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.logger.Info("log-watcher", "started", "Monitoring PHP/web error logs and OS journal", nil)
			a.logTailer.Run(ctx)
		}()
	}

	// 4. Start OS Kernel Firewall Quarantine Enforcer (iptables / Windows netsh advfirewall)
	if a.cfg.FirewallBanEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.logger.Info("firewall", "started", "Enforcing quarantined IP bans at OS firewall", nil)
			a.fwEnforcer.Run(ctx)
		}()
	}

	// 4. Start Local Status / Telemetry Server
	var statusSrv *http.Server
	if a.cfg.StatusAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", a.handleHealthz)
		mux.HandleFunc("/status", a.handleStatus)
		mux.HandleFunc("/events", a.handleEvents)
		mux.HandleFunc("/bans", a.handleBans)

		statusLn, err := net.Listen("tcp", a.cfg.StatusAddr)
		if err != nil {
			return fmt.Errorf("listen status_addr %q: %w", a.cfg.StatusAddr, err)
		}
		statusSrv = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := statusSrv.Serve(statusLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case errCh <- fmt.Errorf("status server: %w", err):
				default:
				}
			}
		}()
	}

	// 5. Start Reverse Proxy HTTP Shield
	var proxySrv *http.Server
	if a.cfg.ProxyEnabled && a.proxy != nil {
		proxyLn, err := net.Listen("tcp", a.cfg.ListenAddr)
		if err != nil {
			if statusSrv != nil {
				_ = statusSrv.Close()
			}
			return fmt.Errorf("listen listen_addr %q: %w", a.cfg.ListenAddr, err)
		}
		proxySrv = &http.Server{
			Handler:           a.proxy,
			MaxHeaderBytes:    a.cfg.MaxHeaderBytes,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       a.cfg.RequestReadTimeout,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       60 * time.Second,
			ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
				return waf.WithReadDeadlineConn(ctx, conn)
			},
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxySrv.Serve(proxyLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case errCh <- fmt.Errorf("proxy server: %w", err):
				default:
				}
			}
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errCh:
		runErr = err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if proxySrv != nil {
		_ = proxySrv.Shutdown(shutdownCtx)
	}
	if statusSrv != nil {
		_ = statusSrv.Shutdown(shutdownCtx)
	}

	wg.Wait()
	a.logger.Info("agent", "shutdown", "PHP2Shell Sentinel stopped cleanly", nil)
	return runErr
}

func (a *Agent) runStartupHardening() {
	iniFiles := hardener.DiscoverINIFiles(a.cfg.PHPSearchPaths)
	for _, f := range iniFiles {
		rep := hardener.AuditAndHardenFile(f, true, false)
		if rep.Modified {
			a.logger.Log(audit.Event{
				Severity:  audit.SeverityInfo,
				Component: "hardener",
				Action:    "ini_hardened",
				Path:      rep.Path,
				Message:   "Hardened php.ini (session.upload_progress.enabled = Off, session.use_only_cookies = On)",
				Metadata:  map[string]string{"backup": rep.BackupPath},
				Mitigated: true,
			})
		}
	}
}

// BuildStatusReport generates a live snapshot of agent health, memory usage, metrics, bans, and alerts.
func (a *Agent) BuildStatusReport() StatusReport {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	now := time.Now().UTC()

	return StatusReport{
		Agent:         "php2shell-sentinel",
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Mode:          a.cfg.Mode,
		UptimeSeconds: int64(now.Sub(a.startedAt).Seconds()),
		Goroutines:    runtime.NumGoroutine(),
		HeapAllocKB:   mem.HeapAlloc / 1024,
		SysMemKB:      mem.Sys / 1024,
		Metrics:       a.logger.MetricsSnapshot(),
		ActiveBans:    a.tracker.ActiveBans(now),
		RecentEvents:  a.logger.RecentEvents(50),
	}
}

func (a *Agent) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

func (a *Agent) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeStatus(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(a.BuildStatusReport())
}

func (a *Agent) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeStatus(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(a.logger.RecentEvents(100))
}

func (a *Agent) handleBans(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete && a.cfg.StatusAuthToken == "" {
		http.Error(w, "status API write access is disabled without status_auth_token", http.StatusForbidden)
		return
	}
	if !a.authorizeStatus(w, r) {
		return
	}
	if r.Method == http.MethodDelete {
		ip := r.URL.Query().Get("ip")
		if ip != "" && a.tracker.Unban(ip) {
			a.logger.Info("intel", "manual_unban", "Removed quarantine ban for IP "+ip, nil)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(a.tracker.ActiveBans(time.Now().UTC()))
}

func (a *Agent) authorizeStatus(w http.ResponseWriter, r *http.Request) bool {
	if a.cfg.StatusAuthToken == "" {
		return true
	}

	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || len(token) != len(a.cfg.StatusAuthToken) ||
		subtle.ConstantTimeCompare([]byte(token), []byte(a.cfg.StatusAuthToken)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="php2shell-sentinel-status"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}
