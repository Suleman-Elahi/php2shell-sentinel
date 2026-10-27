# PHP2Shell Sentinel — Configuration Guide (`sentinel.json`)

This guide provides ready-to-use JSON configurations for common deployment scenarios, followed by a plain-English reference for every setting.

---

## Quick Start: Where Does `sentinel.json` Live?

| Platform | Default Service Config Path | How to Apply Changes |
| :--- | :--- | :--- |
| **Linux (`systemd`)** | `/etc/php2shell-sentinel/sentinel.json` | `sudo systemctl restart php2shell-sentinel` |
| **Windows Service** | `C:\ProgramData\php2shell-sentinel\sentinel.json` | `Restart-Service PHP2ShellSentinel` |
| **Manual CLI Run** | Any path passed via `-config /path/to/sentinel.json` | Restart the `sentinel run` process |

> **Tip:** You do **not** have to specify every field in `sentinel.json`. Any field you omit automatically falls back to Sentinel's safe built-in defaults (see [`configs/sentinel.example.json`](configs/sentinel.example.json) for the full template).

### Duration Values in JSON (Quick Cheat Sheet)

Because Sentinel uses Go's standard `time.Duration` encoding in JSON, time intervals in `sentinel.json` are written in **nanoseconds**:

| Human Time | JSON Value (`nanoseconds`) | Where It's Commonly Used |
| :--- | :--- | :--- |
| `10 ms` | `10000000` | `proc_burst_interval` (fast process scan after WAF alert) |
| `150 ms` | `150000000` | `proc_poll_interval` (normal process tree scan) |
| `250 ms` | `250000000` | `session_poll_interval` (session directory scan) |
| `900 ms` | `900000000` | `multipart_chunk_timeout` (UAF stall breaker deadline) |
| `5 seconds` | `5000000000` | `proc_burst_window` |
| `30 seconds` | `30000000000` | `request_read_timeout` |
| `60 seconds` (`1m`) | `60000000000` | `probe_window` |
| `1 hour` (`1h`) | `3600000000000` | `ban_duration` |

---

## Scenario 1: Day-1 Safe Observation ("Monitor-Only" Mode)

**Best for:** Your first 24–48 hours on a busy production server when you want full visibility and audit logs **without** blocking requests, modifying session files, killing processes, or adding firewall rules.

```json
{
  "mode": "monitor",
  "proxy_enabled": false,
  "session_guard_enabled": true,
  "delete_poisoned_sessions": false,
  "proc_watch_enabled": true,
  "kill_suspicious_exec": false,
  "log_watch_enabled": true,
  "firewall_ban_enabled": false,
  "log_file": "/var/log/php2shell-sentinel.log",
  "log_format": "json"
}
```

**What happens in this mode:**
- Every detector runs and scores suspicious activity in `/var/log/php2shell-sentinel.log` and `sentinel status`.
- **Nothing is killed, deleted, or blocked.** Once you confirm zero false positives in your environment, switch `"mode"` to `"block"` (see Scenario 2 or Scenario 3).

---

## Scenario 2: Zero-Touch Out-of-Band Protection (No Web Port Changes)

**Best for:** Servers where you **cannot** change Nginx/Apache ports right now (or where Nginx talks to PHP-FPM over a Unix socket like `/run/php/php8.2-fpm.sock`), and you want immediate host-level protection against poisoned sessions, spawned shells, and repeat attackers.

```json
{
  "mode": "block",
  "proxy_enabled": false,
  "session_guard_enabled": true,
  "session_dirs": [
    "/var/lib/php/sessions",
    "/tmp"
  ],
  "quarantine_dir": "/tmp/php2shell-sentinel-quarantine",
  "delete_poisoned_sessions": true,
  "scrub_upload_progress_in_place": true,
  "proc_watch_enabled": true,
  "kill_suspicious_exec": true,
  "log_watch_enabled": true,
  "error_log_paths": [
    "/var/log/nginx/error.log",
    "/var/log/php8.2-fpm.log"
  ],
  "firewall_ban_enabled": true,
  "ban_duration": 3600000000000,
  "log_file": "/var/log/php2shell-sentinel.log",
  "log_format": "json"
}
```

**Why this is safe for production:**
- **No traffic rerouting:** Your web server continues listening on `:80`/`:443` untouched.
- **Preserves active user logins:** `"scrub_upload_progress_in_place": true` removes only injected `upload_progress_*` entries from active `sess_*` files while keeping `user_id`, cart, and CSRF session data intact. Confirmed exploit payloads (`<?php`, `|O:` gadgets) are quarantined and deleted immediately.
- **Spares CLI & queue workers:** `composer`, `php artisan queue:work`, `horizon`, `phpunit`, and `wp-cli` are ignored by default; only web SAPI workers (`php-fpm`, `php-cgi`, `apache2`, `httpd`, `php -S`) are watched for shell spawning.

---

## Scenario 3: `Nginx -> Sentinel -> PHP` In-Line WAF (Recommended Production Setup)

**Best for:** Full pre-parser protection. Nginx terminates HTTPS on `:443` and serves static assets, then forwards PHP requests to Sentinel (`127.0.0.1:8080`). Sentinel inspects multipart streams in real time and forwards clean requests to your local PHP HTTP backend (`127.0.0.1:8081`).

### 1. `/etc/php2shell-sentinel/sentinel.json`

```json
{
  "mode": "block",
  "proxy_enabled": true,
  "listen_addr": "127.0.0.1:8080",
  "backend_url": "http://127.0.0.1:8081",
  "trusted_proxies": [
    "127.0.0.1/32",
    "::1/128"
  ],
  "client_ip_header": "X-Forwarded-For",
  "max_body_bytes": 16777216,
  "multipart_chunk_timeout": 900000000,
  "request_read_timeout": 30000000000,
  "block_upload_progress": true,
  "strip_upload_progress": true,
  "inspect_responses": true,
  "scrub_php_version_in_body": true,
  "session_guard_enabled": true,
  "scrub_upload_progress_in_place": true,
  "proc_watch_enabled": true,
  "kill_suspicious_exec": true,
  "log_watch_enabled": true,
  "firewall_ban_enabled": true,
  "ban_duration": 3600000000000,
  "log_file": "/var/log/php2shell-sentinel.log",
  "log_format": "json"
}
```

### 2. Matching Nginx Virtual Host Snippet

```nginx
# Outer Nginx (:443 HTTPS) -> Sentinel WAF (127.0.0.1:8080) -> Internal PHP vhost (127.0.0.1:8081)
location / {
    proxy_http_version 1.1;
    proxy_request_buffering off; # Critical: lets Sentinel inspect upload chunks in real time
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_pass http://127.0.0.1:8080;
}
```

> **Behind Docker, AWS ALB, or Cloudflare?**
> Add your load balancer or Docker bridge CIDR (for example `"172.16.0.0/12"` or `"10.0.0.0/8"`) to `"trusted_proxies"`. Sentinel walks `X-Forwarded-For` from right to left and picks the first non-trusted IP so attackers cannot spoof `X-Forwarded-For`, and Sentinel never accidentally bans your Nginx or load balancer IP.

---

## Scenario 4: Busy Laravel / Symfony / WordPress Site (Queues, Media Tools, & Large Uploads)

**Best for:** Applications that:
1. Accept larger file uploads (e.g., `50 MiB` PDFs/videos) that need a longer upload read timeout.
2. Spawn legitimate helper binaries from web requests (such as `ffmpeg`, ImageMagick `convert`, `gs`, or `wkhtmltopdf`).
3. Run custom background PHP daemons or legitimately use PHP's native `session.upload_progress`.

```json
{
  "mode": "block",
  "proxy_enabled": true,
  "listen_addr": "127.0.0.1:8080",
  "backend_url": "http://127.0.0.1:8081",
  "trusted_proxies": [
    "127.0.0.1/32",
    "::1/128"
  ],
  "max_body_bytes": 52428800,
  "multipart_chunk_timeout": 2000000000,
  "request_read_timeout": 120000000000,
  "max_concurrent_multipart_per_ip": 8,
  "session_guard_enabled": true,
  "scrub_upload_progress_in_place": true,
  "allow_benign_upload_progress": false,
  "proc_watch_enabled": true,
  "kill_suspicious_exec": true,
  "allowed_parent_cmdline_patterns": [
    "artisan",
    "composer",
    "phpunit",
    "pest",
    "wp-cli",
    "drush",
    "bin/console",
    "messenger:consume",
    "queue:work",
    "queue:listen",
    "schedule:run",
    "horizon",
    "vendor/bin/"
  ],
  "allowed_child_cmdline_patterns": [
    "/usr/bin/ffmpeg",
    "/usr/bin/ffprobe",
    "/usr/bin/convert",
    "/usr/local/bin/wkhtmltopdf"
  ],
  "log_file": "/var/log/php2shell-sentinel.log",
  "log_format": "json"
}
```

**Key adjustments in this configuration:**
- `"max_body_bytes": 52428800` raises the maximum request body size to **50 MiB**.
- `"request_read_timeout": 120000000000` allows up to **120 seconds** for slow mobile clients to finish uploading large files.
- `"allowed_child_cmdline_patterns"` lets PHP web workers invoke `/usr/bin/ffmpeg`, `/usr/bin/convert`, or `/usr/local/bin/wkhtmltopdf` without triggering `P2S-PROC-EXEC`, while still killing `/bin/sh`, `bash`, `curl`, `nc`, `python`, or reverse shells.
- If your site intentionally uses PHP's native `session.upload_progress` for upload progress bars, set `"block_upload_progress": false`, `"strip_upload_progress": false`, and `"allow_benign_upload_progress": true` (Sentinel will still block `<?php` code tags, `|O:` object injection, and `> 4 MiB` session inflation).

---

## Scenario 5: Direct Edge HTTPS Termination (No Nginx in Front)

**Best for:** Standalone servers where Sentinel listens directly on `:443` (or `:8443`) with a TLS certificate and forwards clean HTTP traffic to Apache, IIS, or PHP-CGI on `127.0.0.1:8081`.

```json
{
  "mode": "block",
  "proxy_enabled": true,
  "listen_addr": "0.0.0.0:443",
  "backend_url": "http://127.0.0.1:8081",
  "tls_cert_file": "/etc/letsencrypt/live/example.com/fullchain.pem",
  "tls_key_file": "/etc/letsencrypt/live/example.com/privkey.pem",
  "trusted_proxies": [],
  "session_guard_enabled": true,
  "proc_watch_enabled": true,
  "log_watch_enabled": true,
  "firewall_ban_enabled": true,
  "log_file": "/var/log/php2shell-sentinel.log",
  "log_format": "json"
}
```

---

## Scenario 6: Windows Server (IIS / XAMPP / WAMP / Laragon)

**Best for:** Windows deployments (`C:\ProgramData\php2shell-sentinel\sentinel.json`) running either in-line in front of IIS/Apache or out-of-band watching Windows temp session directories, Win32 processes, and Windows Firewall (`netsh advfirewall`).

```json
{
  "mode": "block",
  "proxy_enabled": true,
  "listen_addr": "127.0.0.1:8080",
  "backend_url": "http://127.0.0.1:8081",
  "trusted_proxies": [
    "127.0.0.1/32",
    "::1/128"
  ],
  "session_guard_enabled": true,
  "session_dirs": [
    "C:\\Windows\\Temp",
    "C:\\xampp\\tmp",
    "C:\\wamp64\\tmp",
    "C:\\laragon\\tmp"
  ],
  "quarantine_dir": "C:\\Windows\\Temp\\php2shell-sentinel-quarantine",
  "delete_poisoned_sessions": true,
  "scrub_upload_progress_in_place": true,
  "proc_watch_enabled": true,
  "kill_suspicious_exec": true,
  "log_watch_enabled": true,
  "error_log_paths": [
    "C:\\xampp\\apache\\logs\\error.log",
    "C:\\xampp\\php\\logs\\php_error_log"
  ],
  "firewall_ban_enabled": true,
  "ban_duration": 3600000000000,
  "log_file": "C:\\ProgramData\\php2shell-sentinel\\sentinel.log",
  "log_format": "json"
}
```

> **Note for Windows Out-of-Band Mode:** If you do not want to put Sentinel in-line on port `8080`, simply change `"proxy_enabled": true` to `"proxy_enabled": false`.

---

## Complete Configuration Reference

| JSON Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `mode` | `string` | `"block"` | `"block"` (enforce WAF blocks, session scrubbing, process kills), `"monitor"` (log & score only), or `"quarantine"`. |
| `proxy_enabled` | `bool` | `false` | Enables the in-line HTTP reverse-proxy WAF on `listen_addr`. |
| `listen_addr` | `string` | `"127.0.0.1:8080"` | TCP `host:port` where Sentinel's in-line WAF listens when `proxy_enabled` is `true`. |
| `backend_url` | `string` | `"http://127.0.0.1:8081"` | Upstream PHP web server URL (`http://` or `https://`) receiving clean traffic. |
| `tls_cert_file` | `string` | `""` | Optional PEM certificate path for native HTTPS termination on `listen_addr`. |
| `tls_key_file` | `string` | `""` | Optional PEM private key path for native HTTPS termination on `listen_addr`. |
| `trusted_proxies` | `[]string` | `["127.0.0.1/32", "::1/128"]` | Proxy IPs/CIDRs allowed to supply `X-Forwarded-For` / `X-Real-IP`. |
| `client_ip_header` | `string` | `"X-Forwarded-For"` | Header used to extract the real client IP when the connection comes from `trusted_proxies`. |
| `status_addr` | `string` | `"127.0.0.1:9095"` | Local status & telemetry API bind address (`sentinel status`). |
| `status_auth_token` | `string` | `""` | Bearer token required for status API access and `DELETE /bans` (prefer `SENTINEL_STATUS_AUTH_TOKEN` env var). |
| `status_allow_remote` | `bool` | `false` | Must be `true` (with a non-empty `status_auth_token`) to bind `status_addr` to a non-loopback IP. |
| `max_body_bytes` | `int64` | `8388608` (8 MiB) | Maximum allowed HTTP request body size through the WAF. |
| `max_header_bytes` | `int` | `65536` (64 KiB) | Maximum HTTP request header size. |
| `max_filename_length` | `int` | `200` | Maximum multipart `filename` length (blocks 231-byte `ZendMM` heap spray & session inflation). |
| `max_nested_brackets` | `int` | `16` | Maximum nested array brackets `a[][a]...` in form fields (blocks 62-key scanner/heap-shaping probes). |
| `max_multipart_parts` | `int` | `64` | Maximum multipart parts per request. |
| `max_concurrent_multipart_per_ip` | `int` | `4` | Maximum simultaneous in-flight multipart uploads per client IP (defeats 149-worker pinning). |
| `multipart_chunk_timeout` | `duration` | `900000000` (900ms) | Maximum pause between multipart body chunks when `Cookie: PHPSESSID` is present (UAF stall breaker). |
| `request_read_timeout` | `duration` | `30000000000` (30s) | Overall HTTP request read timeout on `listen_addr`. |
| `block_upload_progress` | `bool` | `true` | Rejects requests containing `PHP_SESSION_UPLOAD_PROGRESS` with `403 Forbidden`. |
| `strip_upload_progress` | `bool` | `true` | Neutralizes `PHP_SESSION_UPLOAD_PROGRESS` field names in streaming multipart bodies. |
| `block_session_id_in_body` | `bool` | `true` | Blocks `name="PHPSESSID"` in multipart bodies (session fixation bypass protection). |
| `block_chunked_multipart` | `bool` | `true` | Blocks `Transfer-Encoding: chunked` on `multipart/form-data` (`post_max_size` OOM bypass). |
| `block_session_lfi` | `bool` | `true` | Blocks LFI paths referencing `sess_*` or `pearcmd.php`. |
| `block_scanner_probes` | `bool` | `true` | Blocks `php2shell-scanner` / `php2shell-checker` structural probes. |
| `inspect_responses` | `bool` | `true` | Inspects upstream PHP responses for `800 KB` `Set-Cookie` heap leaks and OOM bailout signatures. |
| `scrub_php_version_in_body` | `bool` | `true` | Scrubs `PHP x.y.z` version strings in small (`<= 64 KiB`) uncompressed text/HTML/JSON responses. |
| `session_guard_enabled` | `bool` | `true` | Enables real-time scanning of PHP session directories (`sess_*`). |
| `session_poll_interval` | `duration` | `250000000` (250ms) | Poll interval for scanning session directories. |
| `max_session_file_bytes` | `int64` | `4194304` (4 MiB) | Quarantines/deletes `sess_*` files inflated beyond this size (`P2S-SESS-INFLATE`). |
| `delete_poisoned_sessions` | `bool` | `true` | Removes poisoned session files after saving a forensic copy to `quarantine_dir`. |
| `scrub_upload_progress_in_place` | `bool` | `true` | Atomically strips benign `upload_progress_*` keys from active session files instead of deleting the whole session. |
| `allow_benign_upload_progress` | `bool` | `false` | Leaves benign `upload_progress_*` session arrays untouched while still blocking `<?php` and `\|O:` payloads. |
| `proc_watch_enabled` | `bool` | `true` | Enables OS process-tree monitoring for shells spawned by PHP web workers. |
| `proc_poll_interval` | `duration` | `150000000` (150ms) | Normal process-tree sampling interval. |
| `proc_burst_interval` | `duration` | `10000000` (10ms) | Fast process-tree sampling interval triggered immediately after a WAF alert. |
| `proc_burst_window` | `duration` | `5000000000` (5s) | Duration of fast burst sampling after a WAF alert. |
| `kill_suspicious_exec` | `bool` | `true` | Terminates suspicious shell/recon child processes spawned by PHP web workers. |
| `max_worker_rss_mb` | `int` | `0` (disabled) | Optional per-worker RSS ceiling (in MiB) for terminating runaway PHP workers. |
| `allowed_parent_cmdline_patterns` | `[]string` | `["artisan", "composer", ...]` | Substrings in parent command lines that exempt CLI/queue workers from `proc-watch`. |
| `allowed_child_cmdline_patterns` | `[]string` | `[]` | Substrings in child command lines that web workers are permitted to execute (e.g. `"/usr/bin/ffmpeg"`). |
| `log_watch_enabled` | `bool` | `true` | Tails error logs and OS journals (`journalctl` / `wevtutil`) for PHP crashes and OOM bailouts. |
| `firewall_ban_enabled` | `bool` | `false` | Syncs quarantined attacker IPs to `iptables` (Linux) or `netsh advfirewall` (Windows). |
| `ban_threshold_score` | `int` | `100` | Threat score at which an IP is quarantined. |
| `probe_threshold` | `int` | `3` | Number of suspicious probes within `probe_window` that triggers an automatic quarantine. |
| `probe_window` | `duration` | `60000000000` (60s) | Sliding window for counting repeated attacker probes. |
| `ban_duration` | `duration` | `3600000000000` (1h) | How long a quarantined IP remains banned. |

---

## Environment Variable Overrides

Any setting below can also be overridden via environment variables (useful for Docker, Kubernetes, or `systemd` drop-in files):

- `SENTINEL_MODE` (`block`, `monitor`, `quarantine`)
- `SENTINEL_PROXY_ENABLED` (`true` / `false`)
- `SENTINEL_LISTEN_ADDR` (e.g. `127.0.0.1:8080`)
- `SENTINEL_BACKEND_URL` (e.g. `http://127.0.0.1:8081`)
- `SENTINEL_TLS_CERT_FILE` / `SENTINEL_TLS_KEY_FILE`
- `SENTINEL_TRUSTED_PROXIES` (comma-separated, e.g. `127.0.0.1/32,10.0.0.0/8`)
- `SENTINEL_CLIENT_IP_HEADER` (e.g. `X-Forwarded-For` or `CF-Connecting-IP`)
- `SENTINEL_STATUS_ADDR` / `SENTINEL_STATUS_AUTH_TOKEN` / `SENTINEL_STATUS_ALLOW_REMOTE`
- `SENTINEL_LOG_FILE` / `SENTINEL_LOG_FORMAT` (`json` or `text`)
- `SENTINEL_FIREWALL_BAN` (`true` / `false`)
