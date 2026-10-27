# Sentinel Agent – Production Readiness Plan

Addresses feedback from external review. Two themes: (A) reduce collateral
damage from out-of-band guards, (B) fix identity handling in the inline proxy.

---

## Track A: Process Watchdog (`internal/procwatch/`)

### Task A1 — Restrict the RSS rule to web-serving workers
**Risk:** RSS kill matches any process *named* `php`, so CLI queue workers
named `php` get killed when a host sets `max_worker_rss_mb`
(`watcher.go:154-183`, `config.go:150` default 0).
**Work:**
- Match RSS kills only against fpm/cgi/web-server SAPI names
  (`php-fpm*`, `php-cgi*`, `apache2`, `httpd`, …), not bare `php`.
- Add `rss_protected_names` config so hosts can exclude specific workers.
- Document that `max_worker_rss_mb` applies only to web-facing workers.
**Accept:** a `php artisan`/queue worker at 600 MB is not killed; an fpm
worker over the ceiling still is.

### Task A2 — Protect legitimate long-lived children of PHP parents
**Risk:** security tooling invoked from a web request (non-interactive) dies
at `P2S-PROC-EXEC` (`watcher.go:185-242`).
**Work:**
- Add `allowed_child_names` / `allowed_child_cmdline_regex` whitelist
  (e.g. `wp-cli`, `wp`, `composer`, `php`, `git`, `rsync`).
- Add `max_child_age_seconds` (default 180): skip killing a child older than
  N — a webshell child acting instantly is already dead or about to be;
  a long-lived cron-style child is legitimate.
- Keep monitor mode as the recommended rollout path (no code change needed).
**Accept:** typical WP-Cron task chain still completes; reverse shells and
`nc`/`socat` are still killed.

### Task A3 — Test suite for collateral-damage cases
- Regression: deploy-script scenario (`php composer.phar install` from a
  web handler) — assert kill reason only fires for non-whitelisted children.

---

## Track B: Session Guard (`internal/sessionguard/`)

### Task B1 — Stop deleting legitimate upload-progress state
**Risk:** `guard.go:169-190` unconditionally deletes any `sess_*` file
containing `upload_progress_` under `P2S-SESS-UPROG`, killing live
resumable uploads on busy sites (default `delete_poisoned_sessions: true`).
**Work:**
- Delete only when the serialized-gadget regex matches (`|O:`/`|C:` paths) —
  i.e. remove the blanket fallback, or downgrade it to log-only.
- When present but benign: optionally truncate/neutralize the field instead
  of unlinking the whole session file (preserves the user's login session).
**Accept:** an active upload with native progress tracking survives to
completion; a poisoned session with a gadget is still removed.

### Task B2 — Config escape hatch + docs
- Add `upload_progress_guard` mode: `off | strict (default) | log`.
- README: explain trade-off when `session.upload_progress.enabled=1` stays on.

### Task B3 — Regression tests
- Benign serialized upload-progress array → file survives.
- Array containing an object gadget → file mitigated.

---

## Track C: Inline Proxy – TLS & Real Client IP (`internal/waf/`, `internal/intel/`)

### Task C1 — Trusted forwarded header support
**Risk:** `intel.ExtractClientIP` (`tracker.go:95-101`) reads only
`RemoteAddr`; with a TLS terminator in front, bans/rate limits/audit logs
all collapse onto `127.0.0.1`.
**Work:**
- New config: `trust_forwarded_from` (CIDR list, default empty = trust
  nobody, current behavior).
- When peer IP matches a trusted CIDR, resolve client IP from
  `X-Forwarded-For` (right-most untrusted hop) or `X-Real-IP`; strip/
  normalize inbound spoofed values.
- Apply in rate limiting, ban store, score tracking, and audit events.
**Accept:** traffic via a front proxy bans the real client; direct
connections still ban the socket peer; clients behind the proxy cannot
spoof `X-Forwarded-*` to evade bans.

### Task C2 — Forward real client IP to the backend
- Proxy `Director` sets `X-Forwarded-For` (append resolved client IP) and
  `X-Real-IP`; delete client-supplied values first.
- Backend logs then attribute requests correctly too.

### Task C3 — Document the TLS deployment model (optional: TLS support)
- The proxy listens plain HTTP only (`agent.go:204`); document supported
  topologies: (a) TLS terminator in front (requires C1/C2 in place),
  (b) sentinel as front with TLS target behind it.
- Optional stretch: `listen_addr_tls` with cert config for terminating at
  the agent. Keep opt-in; C1 is the prerequisite either way.

### Task C4 — Header hygiene
- Strip inbound `X-Sentinel-*` headers in the Director (currently a client
  can inject `X-Sentinel-Shield: active`).
- Test: block responses carry `X-Blocked-By` only from real mitigations.

---

## Suggested order
1. **B1 + B2** — highest user-facing breakage, smallest diff.
2. **A1 + A2** — watchdog collateral, moderate diff + config additions.
3. **C1 + C2** — correctness of bans/logging; needed before anyone runs the
   proxy behind a TLS terminator.
4. **C4, C3, tests (A3, B3)** — hygiene, docs, regression coverage.

## Rollout guidance
- Each host upgrade steps through **monitor mode first** (watch logs for the
  new `P2S-SESS-UPROG`/`P2S-PROC-EXEC` events on their real traffic for a day)
  before enabling block mode.
- README "Known limitations" section updated to reflect all of the above.
