# PHP2Shell Sentinel (`php2shell-sentinel`)

**PHP2Shell Sentinel** is an intelligent, zero-dependency, low-resource cross-platform defense daemon written in Go (`CGO_ENABLED=0` static binary) to detect, log, prevent, and actively mitigate **php2shell** exploits (**CVE-2026-109618** & **CVE-2026-109619**, plus **CVE-2024-4577**) on both **Linux** and **Windows** servers—with first-class protection for unpatched End-of-Life PHP deployments (`5.4` through `8.1`) and vulnerable `8.2`–`8.5` installations.

It supports both **In-Line Reverse Proxy WAF Mode** and **Zero-Touch Out-of-Band HIDS/HIPS Mode** (protecting PHP servers from the outside without modifying PHP code or web server ports).

---

## What Works with "Zero Application Modifications" (`-no-proxy -firewall`)

| Capability | How Sentinel Does It Passively | Requires App Changes? |
| :--- | :--- | :--- |
| **Killing Spawned Shells (`sh`, `cmd.exe`, `powershell.exe`)** | Scans the OS process tree (`/proc` on Linux, Win32 `CreateToolhelp32Snapshot` on Windows) and terminates shell/recon children spawned by PHP workers (`php-fpm`, `php-cgi`, `apache2`, `httpd`, `w3wp.exe`). | **No** |
| **Preempting Corrupted / Runaway Workers** | Monitors per-worker RSS memory and terminates runaway PHP workers via OS signals (`SIGKILL` / `TerminateProcess`). | **No** |
| **Neutralizing Poisoned Session Files (`sess_*`)** | Continuously watches PHP session directories (`/var/lib/php/sessions`, `/tmp`, `C:\Windows\Temp`, `C:\xampp\tmp`) and quarantines/deletes `sess_*` files containing `<?php`, `upload_progress_`, `\|O:`, or `> 4 MiB` inflation. | **No** |
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

## Building Statically for Linux and Windows

```bash
# 1. Compile statically for Linux (amd64)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/sentinel-linux-amd64 ./cmd/sentinel

# 2. Compile statically for Windows Service & CLI (amd64)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/sentinel-windows-amd64.exe ./cmd/sentinel
```

---

## CLI Usage & Background Service Deployment (Linux)

```bash
# 1. Audit local PHP binary and php.ini files (read-only)
./bin/sentinel-linux-amd64 check

# 2. Apply virtual patches to php.ini files (creates .bak backup first)
sudo ./bin/sentinel-linux-amd64 harden

# 3. Install & start as a persistent systemd background service
sudo ./bin/sentinel-linux-amd64 install -config /etc/php2shell-sentinel/sentinel.json
sudo ./bin/sentinel-linux-amd64 start

# 4. Run in Zero-Touch Out-of-Band Mode (no HTTP port changes; watches /proc, sessions, journald & iptables)
sudo ./bin/sentinel-linux-amd64 run -no-proxy -firewall -log-file /var/log/php2shell-sentinel.log

# 5. Verify systemd service status, live telemetry, and journal logs
sudo systemctl status php2shell-sentinel
sudo journalctl -u php2shell-sentinel -f
./bin/sentinel-linux-amd64 status
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

## GitHub Pages Static Site & One-Line Installers (`docs/`)

The `docs/` folder contains a self-contained static HTML/CSS/JS site ready for **GitHub Pages** (`Settings -> Pages -> Deploy from branch -> /docs`), including prebuilt binaries (`docs/downloads/`) and one-line installer scripts:

### Linux One-Line Install (`curl`)
```bash
curl -fsSL "https://suleman-elahi.github.io/php2shell-sentinel/install.sh" | sudo sh
```

### Windows One-Line Install (Elevated PowerShell `irm`)
```powershell
irm "https://suleman-elahi.github.io/php2shell-sentinel/install.ps1" | iex
```

