# PHP2Shell Sentinel (`php2shell-sentinel`)

**PHP2Shell Sentinel** is an intelligent, zero-dependency, low-resource cross-platform defense daemon written in Go (`CGO_ENABLED=0` static binary) to detect, log, prevent, and actively mitigate **php2shell** exploits (**CVE-2026-109618** & **CVE-2026-109619**, plus **CVE-2024-4577**) on both **Linux** and **Windows** servers—with first-class protection for unpatched End-of-Life PHP deployments (`5.4` through `8.1`) and vulnerable `8.2`–`8.5` installations.

It supports both **In-Line Reverse Proxy WAF Mode** and **Zero-Touch Out-of-Band HIDS/HIPS Mode** (protecting PHP servers from the outside without modifying PHP code or web server ports).

> **Deployment default:** the agent starts in **out-of-band mode**. The in-line
> proxy is opt-in because it must be pointed at the real PHP backend. Enable it
> only after setting `proxy_enabled: true` **and** a valid `backend_url`, or by
> passing `-proxy -backend http://127.0.0.1:<port>`. See
> [Deployment modes](#deployment-modes) below.

### Deployment Modes

| Mode | How to run | What it protects | Traffic change |
| :--- | :--- | :--- | :--- |
| **Out-of-band (default)** | `sentinel install` / `sentinel run` | Session-file poisoning, spawned shells, runaway workers, crash/OOM log signals, `php.ini` hardening, optional firewall bans | None |
| **In-line WAF** | `sentinel run -proxy -listen 127.0.0.1:8080 -backend http://127.0.0.1:8081` | Everything above **plus** pre-parser blocking of php2shell multipart, request, cookie, response, and scanner vectors | Route public traffic to `listen_addr`; keep the PHP backend private |

The one-line installer creates a configuration with the proxy **disabled**, so a
fresh install never breaks a host whose PHP backend is not on the guessed
`127.0.0.1:8081` address. Enabling the proxy without a reachable backend is
reported at startup as `backend_unreachable` and would return `502` to clients.

---

## What Works with "Zero Application Modifications" (`-no-proxy -firewall`)

| Capability | How Sentinel Does It Passively | Requires App Changes? |
| :--- | :--- | :--- |
| **Killing Spawned Shells (`sh`, `cmd.exe`, `powershell.exe`)** | Scans the OS process tree (`/proc` on Linux, Win32 `CreateToolhelp32Snapshot` on Windows) and terminates shell/recon children spawned by PHP workers (`php-fpm`, `php-cgi`, `apache2`, `httpd`, `w3wp.exe`). | **No** |
| **Preempting Corrupted / Runaway Workers** | Monitors per-worker RSS memory and terminates runaway PHP workers via OS signals (`SIGKILL` / `TerminateProcess`). | **No** |
| **Neutralizing Poisoned Session Files (`sess_*`)** | Continuously watches PHP session directories (`/var/lib/php/sessions`, `/tmp`, `C:\Windows\Temp`, `C:\xampp\tmp`) and quarantines/deletes `sess_*` files containing `<?php`, `upload_progress_` state, `\|O:` / `\|C:` serialized object gadgets, or `> 4 MiB` inflation. Legitimate `upload_progress_...\|a:` arrays are cleaned as upload-progress state, not mislabelled as handler mismatch. | **No** |
| **Detecting Crashes, `SIGSEGV`, & OOM Bailouts** | Reads directly from `systemd` journal (`journalctl`), Windows Application Event Log (`wevtutil`), and Apache/Nginx/PHP error logs for `in Unknown on line 0` and `Session object destruction failed`. | **No** |
| **Quarantining Attacking IPs at the OS Firewall** | Automatically inserts DROP/Block rules into the host firewall (`iptables` on Linux, Windows Filtering Platform via `netsh advfirewall` on Windows). | **No** |

---

## Multi-Layer Defense Architecture

1. **Layer 1 — Streaming HTTP Reverse-Proxy WAF (`internal/waf`)**
   - **SID 2026100 (`P2S-2026100`)**: Blocks or strips `PHP_SESSION_UPLOAD_PROGRESS` across `POST`, `PUT`, and `PATCH` multipart bodies, including the `Content-Type: multipart/form-data,boundary=...` comma-delimiter parser discrepancy.
   - **UAF Stall Breaker (`P2S-2026100-STALL`)**: Enforces a sub-second inter-chunk read deadline (`900ms < session.upload_progress.min_freq = 1s`) on multipart uploads carrying session cookies, aborting two-phase stalled uploads before `php_session_track_init()` can free `arData` while `rfc1867` holds cached `zval*` pointers.
   - **Mid-Stream Sliding-Window Scanner (`P2S-2026100-STREAM`)**: Continuously inspects large streaming uploads using pooled 32 KiB buffers with overlap preservation, preventing padding bypasses.
   - **SID 2026101 (`P2S-2026101`)**: Blocks `name="PHPSESSID"` in multipart bodies (mitigates PR #22113 `session.use_only_cookies` bypass / session fixation).
   - **SID 2026102 (`P2S-2026102` — Chain A)**: Blocks PHP tags (`<?php`, `<?=`, `<script language="php">`) inside multipart `filename` parameters.
   - **SID 2026103 (`P2S-2026103` — Chain C)**: Blocks `|O:...` / `|C:...` PHP serialized object injection inside upload filenames (`session.serialize_handler` mismatch).
   - **SID 2026104 (`P2S-2026104` — Chain E & Heap Spray)**: Blocks oversized upload filenames (`> 200` bytes), neutralizing both the `231`-byte `ZendMM` 256B bin heap-spray and 10 KB+ session inflation payloads.
   - **SID 2026105 (`P2S-2026105` — Chain D & OOM)**: Blocks `Transfer-Encoding: chunked` on `multipart/form-data` (which bypasses `post_max_size` to trigger `zend_bailout()` in `rfc1867`) and caps multipart parts (`<= 64`).
   - **SID 2026106 (`P2S-2026106` — Chain A LFI / `pearcmd.php`)**: Blocks LFI requests targeting `sess_*` files (`/tmp/sess_`, `/var/lib/php/sessions/sess_`, `C:\Windows\Temp\sess_`) and `pearcmd.php` (`+config-create+`).
   - **SID 2026107 & 2026108 (`P2S-2026107` / `P2S-2026108`)**: Detects `php2shell-scanner` / `php2shell-checker` probes (`boundary=` empty value, malformed `Content-Disposition:name=a;filename=`, and 62+ nested array brackets `a[][a][a]...`).
   - **SID 2026109 (`P2S-2026109` — ASLR Bypass Stage B1/B2)**: Blocks forged binary/URL-encoded `Cookie: PHPSESSID` values containing null bytes, non-ASCII pointers, or lengths `> 64` bytes.
   - **SID 2026111 & 2026112 (`P2S-2026111` / `P2S-2026112` — Response Guard)**: Scrubs `X-Powered-By`, intercepts `Set-Cookie: PHPSESSID` heap/ASLR leaks (`800 KB` uninitialized `ZendMM` chunk leak), and suppresses `Allowed memory size ... in Unknown on line 0` / `Session object destruction failed` responses while immediately banning the source IP.
   - **CVE-2024-4577 (`P2S-20244577`)**: Blocks Windows/Linux PHP-CGI argument injection (`%ADd`, `allow_url_include`, `auto_prepend_file`).

2. **Layer 2 — Behavioral Threat Intelligence & OS Firewall Enforcer (`internal/intel`, `internal/firewall`)**
   - Limits concurrent in-flight multipart uploads per IP (`max_concurrent_multipart_per_ip = 4`), defeating the 149-connection Apache prefork / PHP-FPM worker-pinning technique required by the multi-stage ASLR bypass.
   - Syncs quarantined attacker IPs to `iptables` (Linux) or Windows Filtering Platform (`netsh advfirewall`).

3. **Layer 3 — Real-Time Session File Guard (`internal/sessionguard`)**
   - Incrementally scans Linux (`/var/lib/php/sessions`, `/tmp`) and Windows (`C:\Windows\Temp`, `C:\xampp\tmp`, `C:\laragon\tmp`) session directories using an `mtime + size` cache.

4. **Layer 4 — Native Cross-Platform Process Tree & RSS Watchdog (`internal/procwatch`)**
   - Uses native `/proc` parsing on Linux and `CreateToolhelp32Snapshot` (`kernel32.dll`) on Windows.

5. **Layer 5 — Error Log / OS Journal Tailer & `php.ini` Auto-Hardener (`internal/logwatch`, `internal/hardener`)**
   - Monitors log files + Linux `journalctl` / Windows `wevtutil` Application Event Log and hardens `php.ini` files (`session.upload_progress.enabled = Off`, `session.use_only_cookies = On`) with timestamped backups.

---

## Verification Results (2026-10-23)

The agent was tested against public php2shell PoCs and a deliberately vulnerable
**PHP 8.2.34-FPM + nginx** lab, first without Sentinel to confirm exploitability,
then with the same requests routed through Sentinel.

| Check | Result |
| :--- | :--- |
| Go unit tests (`go test ./...`) | **PASS** — all packages |
| Repository safe lab (harmless replay) | **PASS** — `403`, `P2S-2026100` |
| Public Chain A RCE, no Sentinel | **RCE CONFIRMED** — `uid=33(www-data)` |
| Public Chain A RCE through Sentinel | **BLOCKED** — `403 P2S-2026100`, no command execution |
| `php2shell-scanner`, no Sentinel | **VULNERABLE** |
| `php2shell-scanner` through Sentinel | **BLOCKED** — `403 P2S-2026107-SCAN` (scanner reports `INCONCLUSIVE` on the rejected probe) |
| Rule-by-rule WAF matrix | **19/19 PASS** |
| Process watchdog | **PASS** — killed long-lived shell children, `P2S-PROC-EXEC` |
| Session-file guard | **PASS** — removed/quarantined poisoned `sess_*` files |
| `php.ini` hardener | **PASS** — `upload_progress=Off`, `use_only_cookies=On`, backup created |
| Exact binary as in-line WAF | **PASS** — clean `200`; Chain A `403` |

The full evidence and reproduction harness are kept outside the repository in
the test lab (`REPORT.md`, `rule_matrix.py`, and captured logs).

---

## Building Statically for Linux and Windows

```bash
# 1. Compile statically for Linux (amd64)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/sentinel-linux-amd64 ./cmd/sentinel

# 2. Compile statically for Windows Service & CLI (amd64)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/sentinel-windows-amd64.exe ./cmd/sentinel
```

---

## Deployment Security Requirements

- **Choose the mode deliberately.** The default configuration runs out-of-band
  host guards and does not listen for HTTP traffic. For pre-parser protection,
  set `"proxy_enabled": true`, point `"backend_url"` at the real PHP backend,
  route public traffic to `"listen_addr"`, and keep the PHP backend private.
  Enabling the proxy against a placeholder backend produces `502` responses.
- The proxy validates `listen_addr` and `backend_url` at startup. If the backend
  is unreachable, Sentinel logs a `backend_unreachable` warning in the journal
  and continues running; fix `backend_url` or disable the proxy with
  `-no-proxy` if only out-of-band mode is intended.
- The status API binds to a loopback IP by default. A non-loopback
  `status_addr` requires both `"status_allow_remote": true` and a non-empty
  `"status_auth_token"`. Supply the token through `SENTINEL_STATUS_AUTH_TOKEN`
  rather than committing it to configuration.
- `DELETE /bans` is disabled unless a status token is configured. When a token
  is configured, use `Authorization: Bearer <token>` for status API endpoints.
- `multipart_chunk_timeout` defaults to 900ms and aborts multipart uploads
  that stall between body reads. `request_read_timeout` defaults to 30 seconds
  and limits total request receive time. Set both for the maximum acceptable
  upload duration and inter-chunk pause in the deployment.

These controls complement, but do not replace, patching PHP and disabling
`session.upload_progress.enabled`.

---

## CLI Usage & Background Service Deployment (Linux)

```bash
# 1. Audit local PHP binary and php.ini files (read-only)
./bin/sentinel-linux-amd64 check

# 2. Apply virtual patches to php.ini files (creates .bak backup first)
sudo ./bin/sentinel-linux-amd64 harden

# 3. Install & start as a persistent systemd background service
#    (default: out-of-band guards; proxy_enabled is false)
sudo ./bin/sentinel-linux-amd64 install -config /etc/php2shell-sentinel/sentinel.json
sudo ./bin/sentinel-linux-amd64 start

# 3b. Enable the in-line WAF in /etc/php2shell-sentinel/sentinel.json:
#       "proxy_enabled": true
#       "listen_addr":  "127.0.0.1:8080"
#       "backend_url":  "http://127.0.0.1:8081"   # <- real PHP backend
#     then: sudo systemctl restart php2shell-sentinel
#     and route public traffic to 127.0.0.1:8080 instead of the backend.

# 4. Run in explicit Zero-Touch Out-of-Band Mode (no HTTP port changes; watches /proc, sessions, journald & iptables)
sudo ./bin/sentinel-linux-amd64 run -no-proxy -firewall -log-file /var/log/php2shell-sentinel.log

# 4b. Or run the in-line shield directly (proxy-specific flags imply -proxy)
sudo ./bin/sentinel-linux-amd64 run -listen 127.0.0.1:8080 -backend http://127.0.0.1:8081 -firewall

# 5. Verify systemd service status, live telemetry, and journal logs
sudo systemctl status php2shell-sentinel
sudo journalctl -u php2shell-sentinel -f
./bin/sentinel-linux-amd64 status
# If status_auth_token is configured:
SENTINEL_STATUS_AUTH_TOKEN='your-token' ./bin/sentinel-linux-amd64 status
```

---

## CLI Usage & Background Service Deployment (Windows PowerShell / Administrator CMD)

Run these commands from an **Elevated PowerShell** or **Administrator Command Prompt (`cmd.exe`)**:

```powershell
# 1. Audit local Windows PHP binary (XAMPP / WAMP / Laragon / IIS) and php.ini files (read-only)
.\bin\sentinel-windows-amd64.exe check -path C:\xampp\php

# 2. Apply php.ini virtual patches (session.upload_progress.enabled = Off) with automatic .bak backup
.\bin\sentinel-windows-amd64.exe harden -path C:\xampp\php\php.ini

# 3. Install & start as a native Windows Background Service (Auto-Start via Windows SCM)
.\bin\sentinel-windows-amd64.exe install -config C:\ProgramData\php2shell-sentinel\sentinel.json
.\bin\sentinel-windows-amd64.exe start

# 4. Run in Zero-Touch Out-of-Band Mode on Windows (watches Win32 processes, C:\Windows\Temp\sess_*, Event Log, and Windows Firewall)
.\bin\sentinel-windows-amd64.exe run -no-proxy -firewall -log-file C:\ProgramData\php2shell-sentinel\sentinel.log

# 5. Run with In-Line HTTP Shield Proxy in front of IIS / Apache / PHP-CGI on Windows
#    (-listen/-backend imply -proxy; point backend at the real PHP listener)
.\bin\sentinel-windows-amd64.exe run -listen 127.0.0.1:8080 -backend http://127.0.0.1:8081 -firewall

# 6. Check Windows Service status, query live telemetry, or stop/uninstall the Windows Service
sc.exe query PHP2ShellSentinel
Get-Service PHP2ShellSentinel
.\bin\sentinel-windows-amd64.exe status

# 7. Inspect Windows Firewall block rules created by Sentinel
netsh advfirewall firewall show rule name=all | findstr PHP2ShellSentinel

# 8. Stop or uninstall the Windows Service
.\bin\sentinel-windows-amd64.exe stop
.\bin\sentinel-windows-amd64.exe uninstall
```

---

## Limitations & Operational Notes

- **Sentinel is mitigation, not a PHP patch.** Keep
  `session.upload_progress.enabled = Off` and upgrade to a fixed PHP release
  (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+ for the affected lines).
- **Process scanning is sample-based.** The default 150ms polling interval can
  miss a very short-lived command such as `system('id')`, while reliably
  catching longer-lived shells and reverse-connection helpers. The WAF and
  php.ini hardening are the primary controls.
- **Response-body version disclosure is application-owned.** Sentinel strips
  `X-Powered-By` and quarantines known heap/OOM response leaks, but it does not
  rewrite arbitrary application output. Do not print `PHP_VERSION` in
  production pages; disable `display_errors` and patch the runtime.
- **A blocked probe can look "inconclusive" to scanners.** `php2shell-scanner`
  reports `INCONCLUSIVE` when it receives Sentinel's `403` instead of a PHP
  crash/response. That is expected: the probe never reached PHP. Use Sentinel's
  rule IDs and logs as the source of truth.
- **The 3-probe/60s auto-ban is intentional.** Sequential rule-by-rule testing
  requires a fresh process state, or the ban will mask later rule IDs.
- **Keep the status API local.** If `status_addr` is exposed remotely, enable
  `status_allow_remote` and configure `status_auth_token`; `DELETE /bans` stays
  disabled without a token.
