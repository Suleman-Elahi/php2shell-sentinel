package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/agent"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/hardener"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/service"
)

var version = "1.0.0"

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout, stderr io.Writer) int {
	subcmd := "run"
	if len(args) > 0 {
		first := args[0]
		if first == "--help" || first == "-h" || first == "--version" || first == "-v" || !strings.HasPrefix(first, "-") {
			subcmd = first
			args = args[1:]
		}
	}

	switch subcmd {
	case "run":
		return cmdRun(args, stderr)
	case "check":
		return cmdCheck(args, stdout, stderr)
	case "harden":
		return cmdHarden(args, stdout, stderr)
	case "status":
		return cmdStatus(args, stdout, stderr)
	case "service":
		return cmdService(args, stdout, stderr)
	case "install", "uninstall", "start", "stop", "print-unit":
		// Support top-level service lifecycle commands (`./sentinel install`, `sentinel.exe start`, etc.)
		return cmdService(append([]string{subcmd}, args...), stdout, stderr)
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "php2shell-sentinel v%s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown subcommand %q\n\n", subcmd)
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `PHP2Shell Sentinel v%s — Lightweight Cross-Platform Defense Agent (CVE-2026-109618 / CVE-2026-109619)

Usage:
  sentinel <command> [flags]

Commands:
  run         Run the Sentinel agent (foreground or Windows SCM / Linux systemd background service)
  install     Install Sentinel as an OS background service (Linux systemd / Windows Service)
  start       Start the installed OS background service
  stop        Stop the running OS background service
  uninstall   Remove the OS background service registration
  check       Audit local PHP versions and php.ini files for php2shell exposure (read-only)
  harden      Apply php.ini virtual patches (session.upload_progress.enabled = Off) with backups
  status      Query live telemetry, blocked attacks, and active bans from a running Sentinel
  service     Manage OS service (<install|uninstall|start|stop|status|print-unit>)
  version     Display agent version and platform information

Run "sentinel <command> -h" for command-specific flags.
`, version)
}

func cmdRun(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfgPath := fs.String("config", "", "Path to JSON configuration file")
	listenAddr := fs.String("listen", "", "Override HTTP shield listen address (e.g. 127.0.0.1:8080)")
	backendURL := fs.String("backend", "", "Override upstream PHP backend URL (e.g. http://127.0.0.1:8081)")
	statusAddr := fs.String("status-addr", "", "Override local status API address (e.g. 127.0.0.1:9095)")
	mode := fs.String("mode", "", "Override protection mode: block or monitor")
	logFile := fs.String("log-file", "", "Write structured event logs to this file path")
	logFormat := fs.String("log-format", "", "Log format: json or text")
	proxy := fs.Bool("proxy", false, "Enable the in-line HTTP shield proxy (requires -backend or backend_url in config)")
	noProxy := fs.Bool("no-proxy", false, "Zero-touch out-of-band mode: run host guards (session, process, log/journal, firewall) without HTTP proxy")
	firewallBan := fs.Bool("firewall", false, "Automatically insert OS firewall DROP rules (Linux iptables / Windows netsh advfirewall) for banned IPs")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error loading config: %v\n", err)
		return 1
	}

	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}
	if *backendURL != "" {
		cfg.BackendURL = *backendURL
	}
	if *statusAddr != "" {
		cfg.StatusAddr = *statusAddr
	}
	if *mode != "" {
		cfg.Mode = config.Mode(strings.ToLower(*mode))
	}
	if *logFile != "" {
		cfg.LogFile = *logFile
	}
	if *logFormat != "" {
		cfg.LogFormat = *logFormat
	}
	switch {
	case *noProxy:
		// Out-of-band mode always wins if both flags are supplied.
		cfg.ProxyEnabled = false
	case *proxy || *listenAddr != "" || *backendURL != "":
		// Supplying proxy-specific flags is an explicit request to run in-line.
		cfg.ProxyEnabled = true
	}
	if *firewallBan {
		cfg.FirewallBanEnabled = true
	}

	if err := cfg.Validate(); err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid configuration: %v\n", err)
		return 2
	}

	logger, err := audit.NewLogger(cfg.LogFile, cfg.LogFormat, cfg.LogLevel)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "failed to initialize logger: %v\n", err)
		return 1
	}
	defer logger.Close()

	ag, err := agent.New(cfg, logger)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "failed to initialize sentinel agent: %v\n", err)
		return 1
	}

	exePath, _ := os.Executable()
	svcMgr := service.NewManager(exePath, *cfgPath)

	if err := svcMgr.Run(func(ctx context.Context) error {
		return ag.Run(ctx)
	}); err != nil {
		_, _ = fmt.Fprintf(stderr, "sentinel exited with error: %v\n", err)
		return 1
	}
	return 0
}

type hostAuditReport struct {
	OS        string                   `json:"os"`
	Arch      string                   `json:"arch"`
	PHPBinary *hardener.VersionStatus  `json:"php_binary,omitempty"`
	INIFiles  []hardener.INIFileReport `json:"ini_files"`
}

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "Optional config file")
	phpVersionFlag := fs.String("php-version", "", "Check a specific PHP version string (e.g. 8.4.26)")
	searchPath := fs.String("path", "", "Additional directory or php.ini file to audit")
	jsonOut := fs.Bool("json", false, "Output machine-readable JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error loading config: %v\n", err)
		return 1
	}
	if *searchPath != "" {
		cfg.PHPSearchPaths = append([]string{*searchPath}, cfg.PHPSearchPaths...)
	}

	rep := hostAuditReport{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	if *phpVersionFlag != "" {
		vs := hardener.CheckPHPVersion(*phpVersionFlag)
		rep.PHPBinary = &vs
	} else if out, err := exec.Command("php", "-v").CombinedOutput(); err == nil {
		vs := hardener.CheckPHPVersion(string(out))
		rep.PHPBinary = &vs
	}

	files := hardener.DiscoverINIFiles(cfg.PHPSearchPaths)
	for _, f := range files {
		rep.INIFiles = append(rep.INIFiles, hardener.AuditAndHardenFile(f, false, true))
	}

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return 0
	}

	_, _ = fmt.Fprintf(stdout, "=== PHP2Shell Host Security Audit (%s/%s) ===\n", rep.OS, rep.Arch)
	if rep.PHPBinary != nil {
		statusLabel := "SAFE / PATCHED"
		if rep.PHPBinary.Vulnerable {
			statusLabel = "VULNERABLE"
		}
		_, _ = fmt.Fprintf(stdout, "PHP Binary Version: %s [%s] — %s\n", rep.PHPBinary.RawVersion, statusLabel, rep.PHPBinary.Reason)
	} else {
		_, _ = fmt.Fprintf(stdout, "PHP Binary Version: not found in PATH (use -php-version to check a version)\n")
	}

	if len(rep.INIFiles) == 0 {
		_, _ = fmt.Fprintf(stdout, "Discovered php.ini files: none in search paths\n")
	} else {
		for _, ini := range rep.INIFiles {
			_, _ = fmt.Fprintf(stdout, "  - %s: upload_progress_off=%v, use_only_cookies=%v\n",
				ini.Path, ini.UploadProgressSecured, ini.UseOnlyCookiesSecured)
		}
	}
	return 0
}

func cmdHarden(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("harden", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "Optional config file")
	targetPath := fs.String("path", "", "Specific php.ini or directory to harden")
	dryRun := fs.Bool("dry-run", false, "Preview changes without modifying files")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error loading config: %v\n", err)
		return 1
	}

	roots := cfg.PHPSearchPaths
	if *targetPath != "" {
		roots = []string{*targetPath}
	}

	files := hardener.DiscoverINIFiles(roots)
	if len(files) == 0 {
		_, _ = fmt.Fprintf(stdout, "No php.ini files discovered in %v\n", roots)
		return 0
	}

	for _, f := range files {
		rep := hardener.AuditAndHardenFile(f, true, *dryRun)
		if rep.Error != "" {
			_, _ = fmt.Fprintf(stderr, "[ERROR] %s: %s\n", rep.Path, rep.Error)
			continue
		}
		if rep.Modified {
			if *dryRun {
				_, _ = fmt.Fprintf(stdout, "[DRY-RUN] Would harden %s\n", rep.Path)
			} else {
				_, _ = fmt.Fprintf(stdout, "[HARDENED] %s (backup: %s)\n", rep.Path, rep.BackupPath)
			}
		} else {
			_, _ = fmt.Fprintf(stdout, "[OK] %s already secured\n", rep.Path)
		}
	}
	return 0
}

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:9095", "Status endpoint address of running Sentinel")
	token := fs.String("token", os.Getenv("SENTINEL_STATUS_AUTH_TOKEN"), "Status API bearer token (defaults to SENTINEL_STATUS_AUTH_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+*addr+"/status", nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid status API address %s: %v\n", *addr, err)
		return 2
	}
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	resp, err := client.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "failed to reach Sentinel status API at %s: %v\n", *addr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = fmt.Fprintf(stderr, "status API at %s returned %s\n", *addr, resp.Status)
		return 1
	}
	_, _ = io.Copy(stdout, resp.Body)
	return 0
}

func cmdService(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: sentinel service <install|uninstall|start|stop|status|print-unit> [-config path]")
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "Path to JSON config file for the background service")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	exePath, err := os.Executable()
	if err != nil {
		exePath = os.Args[0]
	}
	exePath, _ = filepath.Abs(exePath)
	absCfg := *cfgPath
	if absCfg != "" {
		absCfg, _ = filepath.Abs(absCfg)
	}

	mgr := service.NewManager(exePath, absCfg)

	switch action {
	case "print-unit":
		_, _ = fmt.Fprintln(stdout, mgr.UnitFileContent())
		return 0
	case "install":
		if err := mgr.Install(); err != nil {
			_, _ = fmt.Fprintf(stderr, "service install failed: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "Service %q installed successfully.\n", mgr.ServiceName)
		return 0
	case "uninstall":
		if err := mgr.Uninstall(); err != nil {
			_, _ = fmt.Fprintf(stderr, "service uninstall failed: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "Service %q uninstalled successfully.\n", mgr.ServiceName)
		return 0
	case "start":
		if err := mgr.Start(); err != nil {
			_, _ = fmt.Fprintf(stderr, "service start failed: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "Service %q started.\n", mgr.ServiceName)
		return 0
	case "stop":
		if err := mgr.Stop(); err != nil {
			_, _ = fmt.Fprintf(stderr, "service stop failed: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "Service %q stopped.\n", mgr.ServiceName)
		return 0
	case "status":
		out, err := mgr.Status()
		_, _ = fmt.Fprintln(stdout, out)
		if err != nil {
			return 1
		}
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown service action %q\n", action)
		return 2
	}
}
