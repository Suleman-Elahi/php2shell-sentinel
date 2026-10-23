# Security Policy

Thanks for caring about the security of PHP2Shell Sentinel. This document
explains what is supported, how to report a problem, and what you can expect.

## Supported versions

| Version | Supported |
| :--- | :--- |
| 1.0.x | ✅ |
| < 1.0 | ❌ |

## What this project is (and is not)

- **It is a mitigation**, not a patch for PHP. Keep
  `session.upload_progress.enabled = Off` and upgrade PHP to a fixed release.
  See [Limitations](README.md#limitations--operational-notes).
- **It is not a replacement for a WAF** in front of every application; its
  rules target the php2shell exploit chains and related PHP parser abuse.
- **It makes no outbound connections.** The agent has no update check, no
  analytics, no crash reporting, and no phone-home. Its only network listeners
  are the loopback status API and (when explicitly enabled) the in-line HTTP
  shield; its only outbound dials are to the configured backend and, when the
  optional firewall enforcer is enabled, local kernel netlink/netsh calls. See
  [Safety & Transparency](README.md#safety-transparency--supply-chain-trust).

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security bugs.

- Open a **private GitHub Security Advisory** on this repository
  (`Security` → *Report a vulnerability*), or
- Email the maintainer via the contact on the
  [GitHub profile](https://github.com/Suleman-Elahi).

Include: affected version/commit, OS and PHP version, reproduction steps or a
minimal config, and impact (what an attacker gains).

### What to expect

| Stage | Target |
| :--- | :--- |
| Acknowledgement | Within 72 hours |
| Triage & confirmation | Within 7 days |
| Fix or mitigation advisory | Best effort, coordinated disclosure preferred |
| Credit | In the release notes, unless you prefer to stay anonymous |

Reports that show the agent can be **bypassed** (an exploit reaches PHP that
the rules claim to block) or that cause **unintended side effects** (killing a
legitimate process, deleting a legitimate session file, breaking benign
traffic) are treated as the highest priority.

## Supply-chain notes for reviewers

- The binary is built with `CGO_ENABLED=0 -trimpath` and published alongside
  SHA-256 checksums in `docs/downloads/SHA256SUMS.txt`.
- The entire source is in this repository; there are no pre-built dependencies,
  vendored blobs, or generated code from third parties (`go.mod` only depends
  on the Go standard library).
- CI (`.github/workflows/ci.yml`) runs `go vet`, `go test -race -shuffle=on`,
  and the safe integration corpus on every push and pull request.
- The installer scripts (`docs/install.sh`, `docs/install.ps1`) download only
  from this project's own GitHub Pages URL and are short enough to read in full
  before running.
