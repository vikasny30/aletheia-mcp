# Changelog

All notable changes to `aletheia-mcp` are documented here. This project follows
[Semantic Versioning](https://semver.org/) and the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

## [0.3.1] - 2026-09-12

### Security
- **Download-then-execute bypass in `aletheia_safe_bash`'s obfuscation filter.**
  The blacklist only matched a payload piped directly into a shell
  (`curl ... | sh`). A command that staged a payload to disk in one step and
  executed it separately (e.g. `curl -o /tmp/s <url> && bash /tmp/s`) was not
  detected, once an operator had already enabled network access via
  `--allow-network`. Not exploitable on a default install, which denies network
  egress unless explicitly allowed. `bash-analyzer.ts` now detects
  interpreter-based and direct/`chmod`-based download-then-exec chains
  regardless of whether they're piped.
- `curl -o/-O/--output/--remote-name` and `wget -O/--output-document` are now
  recognized as filesystem writes, so a session with network access granted but
  write access denied can no longer silently stage files to disk.
- Reported by Artyom Lobanov ([@Morendais](https://github.com/Morendais)).

## [0.3.0] - 2026-09-06

### Added
- **Transparent proxy now exposes Aletheia's own capabilities.** In `--proxy` mode
  the server merges its own tools, resources, and prompts (`aletheia_set_mandate`,
  `aletheia_get_telemetry`, `aletheia://telemetry/*`, etc.) into the wrapped
  downstream server's responses, and synthesizes list responses when the downstream
  server does not implement `resources`/`prompts` at all. Previously these were
  unreachable behind the proxy.
- `--allow-loopback` startup flag and `ALETHEIA_ALLOW_LOOPBACK` environment variable
  to permit requests to `localhost` / `127.0.0.1` dev servers (still blocked by
  default).
- `server.json` for the official MCP registry, and an `mcpName` field in
  `package.json` for npm ownership validation.
- Cross-customer isolation and concurrent-customer scale test harnesses
  (`npm run test:scale:isolation`, `npm run test:scale:concurrent`).
- Demo recording (`assets/demo.gif`, `demo.tape`) showing an S3 block and the
  telemetry audit log.

### Fixed
- **First-use onboarding trap.** Following the README quickstart verbatim
  (no flags) produced a mandate that could never write a file or make a network
  call, with the only suggested remediation pointing at an `operatorSecret` that is
  never configured by that command and cannot be self-granted. Startup flags
  (`--allow-write`, `--allow-network`, `--allow-loopback`, `--allowed-paths`) now
  clearly set the *initial* mandate and are documented as separate from the
  `operatorSecret` gate, which only governs changing an already-running session.
  All six mandate-related remediation strings were rewritten accordingly.
- Documentation links pointed at a private repository; they now point at the public
  [`aletheia-paper`](https://github.com/vikasny30/aletheia-paper).

### Security
- **Round 9** – SQL OS-command escapes, scheme-less SSRF, bare shell metadata IPs,
  wildcard credential-file coverage.
- **Round 10** – `socat` exfiltration channels, decimal/hex-encoded cloud-metadata
  SSRF, `.pgpass`.
- **Round 11** – `curl -T` / `--upload-file` exfiltration, additional cloud
  credential paths, faster quote parsing.
- **Round 12** – further SQL escape sequences, SSRF embedded in SQL, additional
  exfiltration tools, syntax-boundary fixes.
- **Round 13** – bare-string proxy bypass, `/proc/*/environ` reads, `git push`
  exfiltration, smuggled dynamic SQL.
- 155/155 tests pass; p99 latency unchanged (~25–70 µs depending on machine and GC).

### Changed
- README reframed around honest scope: Aletheia is a fast, pattern-based
  pre-execution filter, **not** a sandbox or a formal guarantee. Added an explicit
  "what this is / isn't" callout and a non-exhaustive Known Limitations section
  (no DNS resolution, enumerated pattern coverage, keyword-based S2b detection,
  no independent third-party review yet).
- `package.json` and `mcp.json` descriptions aligned with that framing.

## [0.2.0] - 2026-09-05

- Initial public release on npm.
- Signature S3 (Scope Creep Beyond Mandate) engine: multi-stage Bash
  de-obfuscation, variable-indirection resolution, IFS/brace normalization,
  dual-representation SQL comment analysis, interpreter-escape interception,
  SSRF and cloud-metadata validation, SQL DDL and tautological-predicate guards,
  monotonic mandate escalation guard.
- Signature S2b (Adversarial Prompt Injection) filter with Unicode NFKC and
  zero-width sanitization.
- Two operating modes: direct guard tools and a fail-closed transparent proxy.
- Real-time telemetry resources and audit log.
- Security hardening Rounds 3–8.

[0.3.0]: https://github.com/vikasny30/aletheia-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/vikasny30/aletheia-mcp/releases/tag/v0.2.0
