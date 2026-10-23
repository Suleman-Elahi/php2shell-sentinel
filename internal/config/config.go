package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Mode defines how the Sentinel handles detected threats.
type Mode string

const (
	ModeBlock   Mode = "block"   // Actively block and mitigate attacks
	ModeMonitor Mode = "monitor" // Log and score attacks without blocking HTTP traffic
)

// Config holds the complete configuration for the PHP2Shell Sentinel agent.
type Config struct {
	// General Agent Settings
	Mode       Mode   `json:"mode"`
	LogFile    string `json:"log_file"`
	LogFormat  string `json:"log_format"` // "json" or "text"
	LogLevel   string `json:"log_level"`  // "debug", "info", "warn", "error"
	StatusAddr string `json:"status_addr"`
	// StatusAllowRemote permits a non-loopback status listener. It requires StatusAuthToken.
	StatusAllowRemote bool   `json:"status_allow_remote"`
	StatusAuthToken   string `json:"status_auth_token"`

	// Reverse Proxy / HTTP Shield Settings
	ProxyEnabled            bool          `json:"proxy_enabled"`
	ListenAddr              string        `json:"listen_addr"`
	BackendURL              string        `json:"backend_url"`
	MaxBodyBytes            int64         `json:"max_body_bytes"`
	MaxHeaderBytes          int           `json:"max_header_bytes"`
	InspectWindowBytes      int           `json:"inspect_window_bytes"`
	MaxMultipartParts       int           `json:"max_multipart_parts"`
	MaxArrayDepth           int           `json:"max_array_depth"`
	MaxFilenameLen          int           `json:"max_filename_len"`
	MultipartChunkTimeout   time.Duration `json:"multipart_chunk_timeout"`
	RequestReadTimeout      time.Duration `json:"request_read_timeout"`
	MaxConcurrentMultipart  int           `json:"max_concurrent_multipart_per_ip"`
	UploadProgressFieldName string        `json:"upload_progress_field_name"`
	BlockChunkedMultipart   bool          `json:"block_chunked_multipart"`
	BlockSessionFixation    bool          `json:"block_session_fixation"`
	StripUploadProgress     bool          `json:"strip_upload_progress"`
	StripPoweredBy          bool          `json:"strip_powered_by"`
	InspectResponses        bool          `json:"inspect_responses"`
	MaxSessionIDCookieLen   int           `json:"max_session_id_cookie_len"`
	AllowedUploadPaths      []string      `json:"allowed_upload_paths"`

	// Behavioral Threat Intelligence & Auto-Ban
	RateLimitPerSecond float64       `json:"rate_limit_per_second"`
	RateLimitBurst     int           `json:"rate_limit_burst"`
	BanThresholdScore  int           `json:"ban_threshold_score"`
	BanDuration        time.Duration `json:"ban_duration"`
	MaxTrackedIPs      int           `json:"max_tracked_ips"`
	FirewallBanEnabled bool          `json:"firewall_ban_enabled"`

	// Session File Guard Settings
	SessionGuardEnabled bool          `json:"session_guard_enabled"`
	SessionDirs         []string      `json:"session_dirs"`
	SessionPollInterval time.Duration `json:"session_poll_interval"`
	MaxSessionFileBytes int64         `json:"max_session_file_bytes"`
	QuarantineDir       string        `json:"quarantine_dir"`
	DeletePoisonedSess  bool          `json:"delete_poisoned_sessions"`

	// Process & Memory Watchdog Settings
	ProcWatchEnabled   bool          `json:"proc_watch_enabled"`
	ProcPollInterval   time.Duration `json:"proc_poll_interval"`
	KillSuspiciousExec bool          `json:"kill_suspicious_exec"`
	MaxWorkerRSSMB     uint64        `json:"max_worker_rss_mb"`
	PHPProcessNames    []string      `json:"php_process_names"`
	BlockedChildNames  []string      `json:"blocked_child_names"`

	// Log & OS Journal Tailer Settings
	LogWatchEnabled     bool     `json:"log_watch_enabled"`
	JournalWatchEnabled bool     `json:"journal_watch_enabled"`
	WatchLogFiles       []string `json:"watch_log_files"`

	// Auto-Hardening Settings
	AutoHardenOnStart bool     `json:"auto_harden_on_start"`
	PHPSearchPaths    []string `json:"php_search_paths"`
}

// Default returns a lightweight, production-ready configuration tailored to the host OS.
func Default() *Config {
	cfg := &Config{
		Mode:              ModeBlock,
		LogFile:           "", // stderr by default, or file when specified
		LogFormat:         "json",
		LogLevel:          "info",
		StatusAddr:        "127.0.0.1:9095",
		StatusAllowRemote: false,
		StatusAuthToken:   "",
		// Out-of-band host guards are safe to enable by default. The in-line
		// proxy is opt-in because it must be pointed at the real PHP backend;
		// enabling it against a guessed/placeholder upstream would break traffic.
		ProxyEnabled:            false,
		ListenAddr:              "127.0.0.1:8080",
		BackendURL:              "http://127.0.0.1:8081",
		MaxBodyBytes:            8 * 1024 * 1024, // 8 MiB ceiling to prevent OOM bailout
		MaxHeaderBytes:          32 * 1024,       // 32 KiB header limit
		InspectWindowBytes:      256 * 1024,      // 256 KiB streaming inspection buffer
		MaxMultipartParts:       64,              // Blocks 149-900 part heap-spray / OOM chains
		MaxArrayDepth:           8,               // Blocks 62-64 nested key scanner/OOM probes
		MaxFilenameLen:          200,             // Blocks 231B zend_string bin spray & >10KB session inflation
		MultipartChunkTimeout:   900 * time.Millisecond,
		RequestReadTimeout:      30 * time.Second,
		MaxConcurrentMultipart:  4, // Blocks 149-connection worker-pinning attacks
		UploadProgressFieldName: "PHP_SESSION_UPLOAD_PROGRESS",
		BlockChunkedMultipart:   true,
		BlockSessionFixation:    true,
		StripUploadProgress:     true,
		StripPoweredBy:          true,
		InspectResponses:        true,
		MaxSessionIDCookieLen:   64, // Blocks 800KB PHPSESSID heap/ASLR leak in Set-Cookie
		AllowedUploadPaths:      []string{},
		RateLimitPerSecond:      40.0,
		RateLimitBurst:          80,
		BanThresholdScore:       100,
		BanDuration:             15 * time.Minute,
		MaxTrackedIPs:           8192,
		FirewallBanEnabled:      false,
		SessionGuardEnabled:     true,
		SessionDirs:             defaultSessionDirs(),
		SessionPollInterval:     250 * time.Millisecond,
		MaxSessionFileBytes:     4 * 1024 * 1024, // 4 MiB max session file (blocks 30MB Chain E inflation)
		QuarantineDir:           defaultQuarantineDir(),
		DeletePoisonedSess:      true,
		ProcWatchEnabled:        true,
		ProcPollInterval:        150 * time.Millisecond,
		KillSuspiciousExec:      true,
		MaxWorkerRSSMB:          0, // 0 = disabled unless configured
		PHPProcessNames:         defaultPHPProcessNames(),
		BlockedChildNames:       defaultBlockedChildNames(),
		LogWatchEnabled:         true,
		JournalWatchEnabled:     true,
		WatchLogFiles:           defaultLogFiles(),
		AutoHardenOnStart:       false,
		PHPSearchPaths:          defaultPHPSearchPaths(),
	}
	return cfg
}

func defaultSessionDirs() []string {
	if runtime.GOOS == "windows" {
		dirs := []string{
			`C:\Windows\Temp`,
			`C:\xampp\tmp`,
			`C:\wamp64\tmp`,
			`C:\laragon\tmp`,
		}
		if tmp := os.TempDir(); tmp != "" {
			dirs = append(dirs, tmp)
		}
		return uniqueStrings(dirs)
	}
	return []string{
		"/var/lib/php/sessions",
		"/var/lib/php/session",
		"/var/cpanel/php/sessions",
		"/tmp",
		"/var/tmp",
	}
}

func defaultQuarantineDir() string {
	return filepath.Join(os.TempDir(), "php2shell-sentinel-quarantine")
}

func defaultPHPProcessNames() []string {
	return []string{
		"php-fpm",
		"php-cgi",
		"php",
		"php8.0", "php8.1", "php8.2", "php8.3", "php8.4", "php8.5",
		"apache2",
		"httpd",
		"lshttpd",
		"frankenphp",
		"php.exe",
		"php-cgi.exe",
		"php-win.exe",
		"httpd.exe",
		"w3wp.exe",
		"caddy.exe",
	}
}

func defaultBlockedChildNames() []string {
	return []string{
		"sh",
		"bash",
		"dash",
		"zsh",
		"ash",
		"ksh",
		"nc",
		"ncat",
		"netcat",
		"socat",
		"curl",
		"wget",
		"python",
		"python3",
		"perl",
		"ruby",
		"lua",
		"whoami",
		"id",
		"uname",
		"cmd.exe",
		"powershell.exe",
		"pwsh.exe",
		"wscript.exe",
		"cscript.exe",
		"certutil.exe",
		"bitsadmin.exe",
		"curl.exe",
		"whoami.exe",
		"net.exe",
		"net1.exe",
		"nc.exe",
		"ncat.exe",
		"python.exe",
		"perl.exe",
	}
}

func defaultLogFiles() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\xampp\apache\logs\error.log`,
			`C:\xampp\php\logs\php_error_log`,
			`C:\wamp64\logs\php_error.log`,
			`C:\wamp64\logs\apache_error.log`,
		}
	}
	return []string{
		"/var/log/apache2/error.log",
		"/var/log/httpd/error_log",
		"/var/log/nginx/error.log",
		"/var/log/php-fpm/error.log",
		"/var/log/php8.4-fpm.log",
		"/var/log/php8.3-fpm.log",
		"/var/log/php8.2-fpm.log",
		"/var/log/php8.1-fpm.log",
		"/var/log/php7.4-fpm.log",
	}
}

func defaultPHPSearchPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\php`,
			`C:\xampp\php`,
			`C:\wamp64\bin\php`,
			`C:\laragon\bin\php`,
			`C:\Program Files\PHP`,
			`C:\Program Files (x86)\PHP`,
			`C:\tools\php`,
		}
	}
	return []string{
		"/etc/php",
		"/etc/php.ini",
		"/etc/php.d",
		"/etc/php-fpm.d",
		"/usr/local/etc/php",
		"/usr/local/lib/php.ini",
		"/opt/cpanel",
		"/opt/remi",
		"/etc/opt/remi",
		"/opt/plesk/php",
		"/www/server/php",
	}
}

// Load reads a JSON config file (if path is non-empty) on top of Default(),
// then applies any SENTINEL_* environment variable overrides.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", path, err)
		}
	}
	cfg.ApplyEnv()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ApplyEnv overrides configuration values from SENTINEL_* environment variables.
func (c *Config) ApplyEnv() {
	if v := os.Getenv("SENTINEL_MODE"); v != "" {
		c.Mode = Mode(strings.ToLower(strings.TrimSpace(v)))
	}
	if v := os.Getenv("SENTINEL_LISTEN_ADDR"); v != "" {
		c.ListenAddr = v
	}
	if v := os.Getenv("SENTINEL_BACKEND_URL"); v != "" {
		c.BackendURL = v
	}
	if v := os.Getenv("SENTINEL_STATUS_ADDR"); v != "" {
		c.StatusAddr = v
	}
	if v := os.Getenv("SENTINEL_STATUS_AUTH_TOKEN"); v != "" {
		c.StatusAuthToken = v
	}
	if v := os.Getenv("SENTINEL_LOG_FILE"); v != "" {
		c.LogFile = v
	}
	if v := os.Getenv("SENTINEL_LOG_FORMAT"); v != "" {
		c.LogFormat = strings.ToLower(v)
	}
	if v := os.Getenv("SENTINEL_MAX_BODY_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			c.MaxBodyBytes = n
		}
	}
	if v := os.Getenv("SENTINEL_SESSION_DIRS"); v != "" {
		sep := ":"
		if runtime.GOOS == "windows" {
			sep = ";"
		}
		parts := strings.Split(v, sep)
		var dirs []string
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				dirs = append(dirs, trimmed)
			}
		}
		if len(dirs) > 0 {
			c.SessionDirs = dirs
		}
	}
}

// Validate checks that configuration parameters are within safe bounds.
func (c *Config) Validate() error {
	if c.Mode != ModeBlock && c.Mode != ModeMonitor {
		return fmt.Errorf("invalid mode %q: must be %q or %q", c.Mode, ModeBlock, ModeMonitor)
	}
	if c.MaxBodyBytes <= 0 {
		return fmt.Errorf("max_body_bytes must be > 0")
	}
	if c.RequestReadTimeout <= 0 {
		c.RequestReadTimeout = 30 * time.Second
	}
	if c.ProxyEnabled {
		if c.ListenAddr == "" {
			return fmt.Errorf("listen_addr is required when proxy_enabled is true")
		}
		if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
			return fmt.Errorf("invalid listen_addr %q: %w", c.ListenAddr, err)
		}
		if c.BackendURL == "" {
			return fmt.Errorf("backend_url is required when proxy_enabled is true")
		}
		backend, err := url.Parse(c.BackendURL)
		if err != nil {
			return fmt.Errorf("invalid backend_url %q: %w", c.BackendURL, err)
		}
		if (backend.Scheme != "http" && backend.Scheme != "https") || backend.Host == "" {
			return fmt.Errorf("invalid backend_url %q: must be an absolute http:// or https:// URL", c.BackendURL)
		}
	}
	if c.StatusAddr != "" {
		host, _, err := net.SplitHostPort(c.StatusAddr)
		if err != nil {
			return fmt.Errorf("invalid status_addr %q: %w", c.StatusAddr, err)
		}
		ip := net.ParseIP(host)
		if !c.StatusAllowRemote && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("status_addr %q must bind to a loopback IP unless status_allow_remote is enabled", c.StatusAddr)
		}
		if c.StatusAllowRemote && c.StatusAuthToken == "" {
			return fmt.Errorf("status_auth_token is required when status_allow_remote is enabled")
		}
	}
	if c.InspectWindowBytes <= 0 {
		c.InspectWindowBytes = 256 * 1024
	}
	if c.MaxMultipartParts <= 0 {
		c.MaxMultipartParts = 64
	}
	if c.MaxArrayDepth <= 0 {
		c.MaxArrayDepth = 8
	}
	if c.MaxFilenameLen <= 0 {
		c.MaxFilenameLen = 200
	}
	if c.UploadProgressFieldName == "" {
		c.UploadProgressFieldName = "PHP_SESSION_UPLOAD_PROGRESS"
	}
	if c.MaxSessionIDCookieLen <= 0 {
		c.MaxSessionIDCookieLen = 64
	}
	if c.BanThresholdScore <= 0 {
		c.BanThresholdScore = 100
	}
	if c.BanDuration <= 0 {
		c.BanDuration = 15 * time.Minute
	}
	if c.MaxTrackedIPs <= 0 {
		c.MaxTrackedIPs = 8192
	}
	return nil
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
