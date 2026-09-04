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

We strongly advise deploying `aletheia-mcp` as part of a **defense-in-depth architecture** alongside least-privilege system users and containerized execution environments.
