# Contributing to PHP2Shell Sentinel

Thanks for helping make PHP servers safer. Contributions of all kinds are
welcome: new detection rules, platform support, documentation, and
reproduction cases from real incidents.

## Ground rules

1. **Safety first.** Every change must be reviewable and side-effect
   documented. If a change can kill a process, delete a file, or block
   traffic, it needs a config gate and a test that proves the safe default.
2. **No exploit weaponization.** Contributions may include *detection* logic
   and defensive analysis, but not weaponized exploit code. Reproduction
   cases must use harmless markers (for example `id`, `echo`, or a canary
   file) — see the safe lab under `lab/`.
3. **Tests are mandatory.** CI runs `go vet ./...`, `go test -race -shuffle=on
   ./...` and `go test -tags=integration ./...`. A PR that regresses a rule or
   blocks benign traffic will not be merged.
4. **Document limitations.** If your change narrows or introduces a
   limitation, update `README.md` and the GitHub Pages site (`docs/`) in the
   same PR.

## Development workflow

```bash
# Build and run the full suite (Go 1.24+)
go vet ./...
go test -race -shuffle=on ./...
go test -tags=integration ./...

# Run the vulnerable PHP lab locally (Docker required)
cd lab && docker compose up -d   # see lab/compose.yaml

# Cross-compile release binaries
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/sentinel-linux-amd64 ./cmd/sentinel
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/sentinel-windows-amd64.exe ./cmd/sentinel
```

## Adding or changing a detection rule

- Rule IDs follow the existing scheme (`P2S-<year><serial>`, with a suffix
  for sub-vectors such as `P2S-2026109-COOKIE`).
- Add the rule to `internal/waf/inspector.go`, a test case to
  `internal/waf/waf_test.go`, and documentation rows to `README.md` and
  `docs/index.html`.
- Include a **benign neighbour test**: a request that looks similar but must
  still be allowed. Rules that break legitimate upload-progress state (for
  example `|a:` arrays in filenames) are regressions.

## Pull requests

- Keep PRs focused; one rule or one subsystem per PR.
- Reference the CVE/chain or the issue your change addresses.
- Fill in the PR template: what changed, why, how it was tested, and what
  side effects a reviewer should look for.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please use a private advisory rather than a
public issue.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
