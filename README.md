# Aletheia MCP Server 🛡️

> **Sub-millisecond runtime safety & scope creep (Signature S3) filter for AI agent tool calls.**

[![MCP Compliant](https://img.shields.io/badge/MCP-Protocol%20Compliant-blue.svg)](https://modelcontextprotocol.io)
[![Latency](https://img.shields.io/badge/p99%20Latency-9.0%C2%A0%C2%B5s-brightgreen.svg)](#performance-benchmarks)
[![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-76%20passed-success.svg)](test/s3-scope.test.ts)

Aletheia MCP intercepts tool calls from Claude, Claude Code, and autonomous agents before execution, scores them against **Signature S3 (Scope Creep Beyond Mandate)** and **Signature S2b (Adversarial Prompt Injection)**, and blocks destructive actions with **sub-millisecond (<10 µs) overhead**.

Derived from the [Aletheia Behavioral Observability Framework](https://github.com/vikasny30/aletheia), validated against **2,571 real-world AI failure incidents** from AIID, AVID, and the MIT AI Risk Repository.

---

## Security Model: Defense-in-Depth, Not a Sandbox

Aletheia MCP provides **deterministic, high-performance lexical, syntactic, and structural filtering in single-digit microseconds**. It neutralizes obfuscation, token quote-splitting, shell variable indirection, interpreter escapes, dual-representation SQL comment tricks, and monotonic self-mandate escalation before tools execute.

> [!IMPORTANT]
> **Defense-in-Depth vs. Isolation**:
> Aletheia MCP is an ultra-fast, zero-latency pre-execution gatekeeper designed as a critical layer in a defense-in-depth posture. Lexical analysis against a Turing-complete shell has inherent theoretical asymptotes; Aletheia MCP is **not a substitute** for operating autonomous agents with least-privilege credentials, non-root system users, scoped database grants, and containerized or VM-level sandboxes (e.g., Docker, gVisor, Firecracker). Optimal security combines Aletheia at the MCP tool boundary with OS/network-level sandboxing.

---

## The Problem: Scope Creep (S3) in Agent Runtimes

When autonomous agents are granted tool execution access (Bash, SQL, filesystem mutation, API calls), the primary failure mode is **Scope Creep Beyond Mandate**:

- **Destructive Shell Mutation**: An agent asked to "inspect git diff" runs `git reset --hard` or `rm -rf *` to resolve a conflict.
- **Credential Harvesting**: An agent reading code probes `~/.ssh/id_rsa`, `.env`, or AWS credentials to resolve connection errors.
- **Unbounded Database Writes**: An agent executes `DELETE FROM accounts;` or `UPDATE users SET role='admin';` without `WHERE` predicates (or with tautological `WHERE 1=1`).
- **Interpreter Escape Hatches**: An agent runs shell commands wrapped inside `python3 -c "os.system('...')"` or `node -e "fs.rmSync('/')"`.
- **SSRF & Cloud Metadata Leaks**: An agent probing network endpoints makes calls to `169.254.169.254` (AWS metadata) or internal RFC1918 subnets.
- **Self-Mandate Escalation**: A prompt-injected or drifting agent attempting to rewrite its own safety policy.

Existing defenses rely on LLM-as-a-judge evaluators that add **1,500–3,000 ms** to every tool call. Aletheia MCP provides **deterministic, multi-stage lexical and structural filtering in single-digit microseconds**.

---

## Key Features

- **⚡ Sub-Millisecond (<10 µs p99) Overhead**: Over 270,000 evaluations per second. Zero perceived latency in agent loops.
- **🛡️ Monotonic Mandate Escalation Guard**: Prevents autonomous agents from self-granting write, destructive, or network permissions. Mandates can be tightened voluntarily, but loosening requires an `operatorSecret`.
- **🎯 Evasion-Hardened Engine**:
  - **Quote & Backslash Stripping**: Defeats split-token evasion (`r'm' -rf /`, `r\m -rf /`).
  - **Variable Indirection**: Resolves shell variable substitutions (`X=rm; $X -rf /`).
  - **Positional Parameter & IFS Normalization**: Neutralizes `$IFS$9` word-splitting.
  - **Brace Expansion Resolution**: Expands `{etc,usr}` and single `{etc}` patterns.
  - **Dual-Representation SQL Analysis**: Defeats inline comment evasion (`DROP/**/TABLE` and `DR/**/OP`).
  - **Interpreter Escape Interception**: Recursively normalizes string concatenations (`'r'+'m'`), inspects dynamic imports (`import("node:fs")`), and parses code passed via `-c`/`-e`/`-r` flags across `python`, `node`, `ruby`, `perl`, `php`, and `sh`.
  - **Automated Hex & Base64 Decoding**: Automatically extracts, decodes, and recursively evaluates hex (`bytes.fromhex(...)`) and base64-encoded command payloads.
  - **Unicode NFKC & Zero-Width Sanitization**: Neutralizes invisible characters (`\u200B`, `\u200C`, `\uFEFF`) and confusable fullwidth/math-bold jailbreaks in prompt injections (S2b).
  - **IPv4-Mapped IPv6 SSRF Translation**: Converts compressed hex IPv6 notations (`[::ffff:a9fe:a9fe]`) to canonical dotted-decimal bytes (`169.254.169.254`).
  - **Percent-Encoded Path Traversal**: Multi-pass URL decoding catches `%2e%2e%2f.env` and `..%2f.ssh%2fid_rsa`.
  - **Generalized Fork Bombs**: Detects recursive piped background processes across arbitrary function identifiers.
  - **SetUID Privilege Elevation**: Halts `chmod u+s`, `chmod 4755`, and privilege tampering.
  - **Tautological SQL Predicates**: Flags `WHERE 1=1`, `WHERE true`, and tautologies as unbounded mutations.
  - **Polymorphic Argument Inspection**: Safely inspects strings, arrays, and objects fail-closed across both native and unrecognized third-party tools.
- **🛡️ Two Operating Modes**:
  1. **Direct Guard Tools**: Standalone tools (`aletheia_set_mandate`, `aletheia_intercept`, `aletheia_safe_bash`, `aletheia_safe_sql`).
  2. **Fail-Closed Transparent Proxy**: Middleware that wraps ANY downstream MCP server (Postgres, Filesystem, Bash), intercepting `tools/call` with strict fail-closed boundaries (unhandled exceptions block downstream transmission and emit RFC-compliant `CallToolResult`).
- **📊 Real-Time Observability Resources**: Exposes live audit logs, block rates, and latency distributions via `aletheia://telemetry/summary`.
- **🔒 Zero External API Calls**: Zero LLM-as-a-judge latency on the hot execution path.

---

## Performance Benchmarks

Measured on 10,000 consecutive multi-domain evaluations (Bash de-obfuscation, SQL pattern validation, path verification, SSRF check, prompt injection):

| Metric | Measured Value | Target |
| :--- | :--- | :--- |
| **p50 (Median)** | **0.0033 ms (3.3 µs)** | < 0.500 ms |
| **p95 Latency** | **0.0054 ms (5.4 µs)** | < 0.800 ms |
| **p99 Latency** | **0.0090 ms (9.0 µs)** | < 1.000 ms |
| **Throughput** | **269,000+ evals / second** | > 10,000 / s |
| **Hot-Path External APIs**| **0 (Deterministic local engine)** | 0 |

*Run locally via `npm run benchmark`.*

---

## Quickstart

### 1. Claude Code CLI

Add Aletheia directly to Claude Code in one command:

```bash
claude mcp add aletheia -- npx -y aletheia-mcp
```

### 2. Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aletheia": {
      "command": "npx",
      "args": ["-y", "aletheia-mcp"]
    }
  }
}
```

### 3. Transparent Proxy Mode

Wrap existing downstream MCP servers with Aletheia safety filtering:

```json
{
  "mcpServers": {
    "secure-filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "aletheia-mcp",
        "--allow-write",
        "--proxy",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/path/to/allowed/dir"
      ]
    }
  }
}
```

---

## Tool Reference

| Tool | Mode | Annotation | Description |
| :--- | :--- | :--- | :--- |
| **`aletheia_set_mandate`** | State | `readOnlyHint: false` | Establish or tighten operational safety envelope. Loosening requires `operatorSecret`. |
| **`aletheia_get_mandate`** | Observability | `readOnlyHint: true` | Retrieve active mandate, allowed paths, and risk tolerance. |
| **`aletheia_intercept`** | Gatekeeper | `readOnlyHint: true` | Pre-flight check for candidate tool calls. Returns `ALLOW` or `BLOCK` with violation details. |
| **`aletheia_safe_bash`** | Execution | `readOnlyHint: false` | Verified shell executor. Blocks `rm -rf`, fork bombs, exfiltration before running. |
| **`aletheia_safe_sql`** | Audit | `readOnlyHint: true` | Validates SQL against `DROP`, `TRUNCATE`, and unbounded `DELETE`/`UPDATE` (including `WHERE 1=1`). |
| **`aletheia_get_telemetry`** | Observability | `readOnlyHint: true` | Emits evaluation counts, block rate %, and microsecond latency percentiles. |

---

## Resource & Prompt Reference

### Resources (`resources/read`)
Clients can inspect server state on-demand via standard MCP `resources/read`:
- **`aletheia://telemetry/summary`**: Real-time evaluation counters, block rate %, and microsecond latency distribution.
- **`aletheia://telemetry/audit-log`**: Rolling log of the last 50 tool clearance requests with inputs, verdicts, violation signatures, and timestamps.
- **`aletheia://mandate/current`**: Active session mandate parameters, allowed tool lists, path boundaries, and permission toggles.
- **`aletheia://signatures/s3`**: Specification, risk taxonomy, and benchmark failure rate data for Signature S3 (Scope Creep).

### Prompts (`prompts/get`)
- **`aletheia_mandate_enforcer`**: System prompt directive that establishes operational safety boundaries and instructs the agent to route risky actions through Aletheia before execution. Accepts `task_description` (required), `workspace_root` (optional), and `allow_write` (optional).

---

## Architecture

```
                    ┌───────────────────────────────────────────────┐
                    │          Claude / Agent Host Runtime          │
                    └───────┬───────────────────────────────┬───────┘
                            │                               │
                  Mode 1: Guard Tools              Mode 2: Transparent Proxy
                  (aletheia_intercept,             (Intercepts tools/call
                   aletheia_safe_bash)              to downstream MCPs)
                            │                               │
                            ▼                               ▼
            ┌───────────────────────────────────────────────────────────────┐
            │                      Aletheia MCP Server                      │
            │                                                               │
            │  ┌─────────────────────────────────────────────────────────┐  │
            │  │              S3 Scope Creep Engine (<10µs)              │  │
            │  │  ├─ Multi-stage Token Unquoting & De-obfuscation        │  │
            │  │  ├─ Variable Indirection Resolver                       │  │
            │  │  ├─ Positional IFS & Brace Expansion Normalizer         │  │
            │  │  ├─ Dual-Representation SQL Comment Analyzer            │  │
            │  │  ├─ Interpreter Escape Filter (python -c, node -e)      │  │
            │  │  ├─ Destructive Filter (rm -rf, fork bombs, find -del)  │  │
            │  │  ├─ SetUID / Privilege Escalation Guard                 │  │
            │  │  ├─ Credential & Sensitive File Access Guard            │  │
            │  │  ├─ SSRF & Cloud Metadata Validator                     │  │
            │  │  ├─ SQL DDL & Tautological Predicate Guard (WHERE 1=1)  │  │
            │  │  ├─ Monotonic Mandate Escalation Guard (operatorSecret) │  │
            │  │  └─ S2b Adversarial Prompt Injection Filter             │  │
            │  └─────────────────────────────────────────────────────────┘  │
            │                                                               │
            │  ┌─────────────────────────────────────────────────────────┐  │
            │  │ Telemetry & Audit Stream (aletheia://telemetry/summary) │  │
            │  └─────────────────────────────────────────────────────────┘  │
            └───────────────────────────────┬───────────────────────────────┘
                                            │
                              [ALLOW]       │       [BLOCK]
                    ┌───────────────────────┴───────────────────────┐
                    ▼                                               ▼
          Execute Tool Safely                         Emit Structured Policy Breach
                                                      (Explains boundary violation)
```

---

## Research Attribution & Empirical Corpus

Aletheia MCP is developed by **Vikas Shivpuriya** as part of the broader **Aletheia AI Safety Research Core**. The underlying behavioral failure signatures are derived from empirical evaluations across frontier models (Claude 3.5/4.6, GPT-4o, Gemini 2.5) validated against **2,571 incidents** cataloged in the AI Incident Database (AIID), AVID, and the MIT AI Risk Repository.

- **Research Core & Evaluation Harness**: [github.com/vikasny30/aletheia](https://github.com/vikasny30/aletheia)
- **License**: [Apache 2.0](LICENSE)
