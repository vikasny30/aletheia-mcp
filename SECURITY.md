# Security Policy

## Reporting Security Vulnerabilities & Evasion Bypasses

We welcome and encourage security researchers, agent developers, and the AI safety community to probe and report potential evasion vectors, parser seams, or authorization bypasses in `aletheia-mcp`.

If you discover an evasion technique, privilege escalation vector, or security defect:

1. **Do NOT open a public GitHub issue.**
2. Email full technical details and a reproducible probe to:
   - **Primary Contact**: Vikas Shivpuriya <vikas.ny30@gmail.com>
3. Please include:
   - Command line or JSON-RPC payload reproducing the bypass
   - Expected behavior vs. observed behavior
   - Impact assessment (e.g. destructive FS deletion, credential exfiltration, mandate escalation)
   - Suggested remediation or regex/AST constraint (if known)

### Response Commitment & SLA

- **Acknowledgement**: Within 24 hours of report receipt.
- **Triage & Reproduction**: Within 48 hours.
- **Remediation & Patch Release**: High-severity bypasses patched within 5 business days via npm release and GitHub advisory.

---

## Security Model & Theoretical Scope

`aletheia-mcp` operates as a **pre-execution, sub-millisecond lexical, syntactic, and structural filter**.

### What Aletheia Is:
- A high-speed, zero-overhead first line of defense against accidental or prompt-injected agent tool calls.
- A deterministic enforcer of monotonic session mandates (`operatorSecret` escalation guards).
- A multi-stage normalizer neutralizing shell quote-splitting, variable indirection, interpreter one-liner escapes, and dual-representation SQL comment tricks.

### What Aletheia Is Not:
- A substitute for OS-level sandboxing, container isolation (Docker, gVisor, Firecracker), or kernel-enforced permission barriers (AppArmor, SELinux).
- A guaranteed defense against every theoretical ambiguity in a Turing-complete shell without OS isolation.

### DNS Resolution & Attacker-Controlled Hostnames (SSRF / DNS Rebinding Boundary)

Aletheia inspects literal URLs, IP literals (IPv4, IPv6, IPv4-mapped IPv6, and obfuscated octal/hex encodings), and known cloud metadata hostnames directly from tool input arguments. Aletheia purposefully does **not** perform synchronous, out-of-band DNS resolution on arbitrary domains (e.g. resolving `attacker-domain.example` to check whether its A/AAAA record points to `169.254.169.254` or `127.0.0.1`).

Doing so would:
1. Violate Aletheia's sub-millisecond determinism guarantee (<20 µs p99) by introducing unbounded network I/O latency.
2. Introduce Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding vulnerabilities where the IP resolved by Aletheia differs from the IP contacted by the downstream runtime tool.
3. Potentially trigger attacker-monitored DNS canary exfiltration channels during the check itself.

**Defense-in-depth requirement**: Protection against DNS rebinding attacks targeting private infrastructure or cloud metadata services must be enforced at the OS and network layers:
- Egress firewall rules (e.g. iptables/nftables dropping outbound packets to `169.254.169.254` except for authorized system daemons).
- AWS IMDSv2 hop-limit constraints (`HttpPutResponseHopLimit=1` to prevent container bridge forwarding).
- An egress forward proxy (e.g. Envoy, Squid, Smokescreen) that pins and validates resolved IP addresses before establishing TCP connections.

We strongly advise deploying `aletheia-mcp` as part of a **defense-in-depth architecture** alongside least-privilege system users and containerized execution environments.
