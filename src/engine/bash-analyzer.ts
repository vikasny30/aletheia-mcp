/**
 * Aletheia MCP Server: High-Performance Bash & Shell AST / Lexical Analyzer
 * 
 * Target latency: <0.2ms
 * Detects: Destructive mutations, credential harvesting, privilege escalation,
 * obfuscated execution (base64, hex, subshells, pipe-to-sh), out-of-boundary redirects.
 */

import { Violation, Mandate } from "./types.js";

// Sensitive system and credential patterns
const SENSITIVE_PATH_PATTERNS = [
  /(^|\s|\/)\.env(\.[a-z0-9_-]+)?(\s|$)/i,
  /(^|\s|\/)id_(rsa|ed25519|ecdsa|dsa)(\.pub)?(\s|$)/i,
  /(^|\s|\/)~?\.?ssh(\/[a-z0-9_.-]+)?(\s|$)/i,
  /(^|\s|\/)~?\.?aws\/(credentials|config)(\s|$)/i,
  /(^|\s|\/)~?\.?config\/gcloud(\s|$)/i,
  /(^|\s|\/)~?\.?kube\/config(\s|$)/i,
  /(^|\s|\/)~?\.?npmrc(\s|$)/i,
  /(^|\s|\/)~?\.?netrc(\s|$)/i,
  /(^|\s|\/)\/etc\/(shadow|passwd|master\.passwd|sudoers)(\s|$)/i,
  /(^|\s|\/)\/proc\/kcore(\s|$)/i,
];

// Destructive command signatures (High blast radius)
const DESTRUCTIVE_SIGNATURES: Array<{
  pattern: RegExp;
  description: string;
  type: Violation["type"];
}> = [
  {
    pattern: /\brm\s+(-[a-z]*[rf][a-z]*\s+)+(\/|\/\*|~|\$HOME|\.\.?|\*|\.\/\*|\/tmp\/\*|\/etc|\/usr)(\s|$|;)/i,
    description: "Unbounded filesystem recursive delete (rm -rf root / home / wildcard)",
    type: "DESTRUCTIVE_FS_COMMAND",
  },
  {
    pattern: /\brm\s+-[a-z]*[rf][a-z]*\s+(\/|\/\*|~|\*|\.)(\s|$|;)/i,
    description: "Recursive delete of root, wildcard, or home",
    type: "DESTRUCTIVE_FS_COMMAND",
  },
  {
    pattern: /\b(mkfs(\.[a-z0-9]+)?|dd\s+if=\S+\s+of=\/dev\/(sd[a-z]|nvme\d|disk\d)|fdisk|parted)\b/i,
    description: "Raw disk manipulation or partition formatting tool",
    type: "DESTRUCTIVE_FS_COMMAND",
  },
  {
    pattern: /\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f[a-z]*|push\s+-[a-z]*f[a-z]*|push\s+--force)\b/i,
    description: "Destructive git operation (hard reset, forced clean, or force push)",
    type: "DESTRUCTIVE_FS_COMMAND",
  },
  {
    pattern: /(:(){ :\|:& };:|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:)/,
    description: "Fork bomb process saturation sequence",
    type: "SYSTEM_STABILITY_THREAT",
  },
  {
    pattern: /\b(shutdown|reboot|poweroff|halt|init\s+0)\b/i,
    description: "System shutdown / reboot termination instruction",
    type: "SYSTEM_STABILITY_THREAT",
  },
  {
    pattern: /\bchmod\s+(-[a-z]*R[a-z]*\s+)?(777|0777|a\+rwx)\s+(\/|~|\$HOME|\.\.)/i,
    description: "Broad global permission relaxation (chmod 777 on sensitive root)",
    type: "PRIVILEGE_ESCALATION",
  },
  {
    pattern: /\b(sudo|su\s+-|doas)\b/i,
    description: "Privilege escalation attempt (sudo/su/doas)",
    type: "PRIVILEGE_ESCALATION",
  },
  {
    pattern: /\b(kill\s+-9\s+-1|killall\s+-9\s+(systemd|launchd|init|loginwindow))\b/i,
    description: "Host-level process termination assault",
    type: "SYSTEM_STABILITY_THREAT",
  },
];

// Obfuscation and evasion patterns
const OBFUSCATION_PATTERNS: Array<{
  pattern: RegExp;
  description: string;
}> = [
  {
    pattern: /(curl|wget|fetch)\s+\S+\s*\|\s*(ba|z)?sh/i,
    description: "Remote payload download directly piped into shell execution",
  },
  {
    pattern: /echo\s+[A-Za-z0-9+/=]{8,}\s*\|\s*base64\s+(-d|--decode)\s*\|\s*(ba|z)?sh/i,
    description: "Base64 encoded string piped directly into execution shell",
  },
  {
    pattern: /\$\(\s*echo\s+[A-Za-z0-9+/=]{8,}\s*\|\s*base64\s+(-d|--decode)\s*\)/i,
    description: "Base64 subshell command evaluation",
  },
  {
    pattern: /\b(eval|exec)\s+(\$|`|"|')/i,
    description: "Dynamic code execution via eval/exec construct",
  },
  {
    pattern: /\$'\\[0-9xX]/,
    description: "Hex or octal character escape obfuscation in shell string",
  },
];

// Exfiltration signatures
const EXFILTRATION_PATTERNS: Array<{
  pattern: RegExp;
  description: string;
}> = [
  {
    pattern: /\b(curl|wget)\s+.*(-d\s*@|-F\s*\S*=@|--data-binary\s*@|--post-file\s*)/i,
    description: "Outbound HTTP file transmission / exfiltration pattern",
  },
  {
    pattern: /\b(nc|ncat|netcat)\s+(-[a-z]*e[a-z]*\s+|\S+\s+\d+)/i,
    description: "Netcat reverse shell or raw network exfiltration channel",
  },
];

// Mutation indicators (redirects and file alteration)
const MUTATION_PATTERNS = [
  /(>>?|\|tee\s)/,
  /\b(sed\s+-[a-z]*i|truncate\s+|mv\s+|cp\s+|rm\s+|mkdir\s+|touch\s+)/i,
];

// Network indicators
const NETWORK_COMMANDS = /\b(curl|wget|fetch|nc|ncat|netcat|ssh|scp|sftp|rsync|ping|nmap|telnet|dig|nslookup)\b/i;

export interface BashAnalysis {
  isDestructive: boolean;
  isObfuscated: boolean;
  isWriteAttempt: boolean;
  isNetworkAttempt: boolean;
  isSubshell: boolean;
  normalizedCommand: string;
  violations: Violation[];
  targetPaths: string[];
}

/**
 * Normalizes command text by stripping benign quotes and collapsing spaces
 */
export function normalizeCommand(raw: string): string {
  let cleaned = raw.trim();
  // Strip null bytes
  cleaned = cleaned.replace(/\0/g, "");
  // Collapse whitespace
  cleaned = cleaned.replace(/\s+/g, " ");
  return cleaned;
}

/**
 * Attempts to decode base64 payloads to inspect inner payload
 */
export function extractAndDecodeBase64(command: string): string | null {
  const b64Match = command.match(/base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh/i)
    || command.match(/echo\s+([A-Za-z0-9+/=]{8,})\s*\|\s*base64/i);
  
  if (b64Match) {
    const rawPayload = command.match(/[A-Za-z0-9+/=]{8,}/);
    if (rawPayload) {
      try {
        const decoded = Buffer.from(rawPayload[0], "base64").toString("utf-8");
        return decoded;
      } catch {
        return null;
      }
    }
  }
  return null;
}

/**
 * High-speed deterministic Bash safety analysis (<0.2ms)
 */
export function analyzeBashCommand(rawCommand: string, mandate: Mandate): BashAnalysis {
  const normalized = normalizeCommand(rawCommand);
  const violations: Violation[] = [];

  const isWriteAttempt = MUTATION_PATTERNS.some((p) => p.test(normalized));
  const isNetworkAttempt = NETWORK_COMMANDS.test(normalized);
  const isSubshell = /(`|\$\()/.test(normalized);

  // 1. Check Obfuscation & Evasion Patterns
  for (const { pattern, description } of OBFUSCATION_PATTERNS) {
    if (pattern.test(normalized)) {
      violations.push({
        signature: "S3",
        type: "OBFUSCATION_BYPASS",
        severity: "CRITICAL",
        description,
        evidence: normalized.slice(0, 120),
        remediation: "Execute explicit, transparent commands without piping encoded strings or dynamic eval.",
      });
      break;
    }
  }

  // Also inspect inside decoded base64 if present
  const decodedPayload = extractAndDecodeBase64(normalized);
  if (decodedPayload) {
    violations.push({
      signature: "S3",
      type: "OBFUSCATION_BYPASS",
      severity: "CRITICAL",
      description: `Hidden base64 payload detected: "${decodedPayload.slice(0, 80)}"`,
      evidence: normalized.slice(0, 100),
      remediation: "Disclose all commands transparently in plaintext.",
    });
  }

  // 2. Check Destructive Signatures
  for (const { pattern, description, type } of DESTRUCTIVE_SIGNATURES) {
    if (pattern.test(normalized)) {
      violations.push({
        signature: "S3",
        type,
        severity: "CRITICAL",
        description,
        evidence: normalized.slice(0, 120),
        remediation: "Destructive commands that erase files, partitions, or system states are blocked.",
      });
    }
  }

  // 3. Check Credential & Sensitive Path Access
  for (const pattern of SENSITIVE_PATH_PATTERNS) {
    if (pattern.test(normalized)) {
      violations.push({
        signature: "S3",
        type: "SENSITIVE_FILE_ACCESS",
        severity: "HIGH",
        description: "Attempted read or access to credentials, SSH keys, or OS sensitive secrets",
        evidence: normalized.slice(0, 120),
        remediation: "Do not access .env, private keys, cloud tokens, or /etc secrets.",
      });
      break;
    }
  }

  // 4. Check Exfiltration Signatures
  for (const { pattern, description } of EXFILTRATION_PATTERNS) {
    if (pattern.test(normalized)) {
      violations.push({
        signature: "S3",
        type: "CREDENTIAL_EXFILTRATION",
        severity: "CRITICAL",
        description,
        evidence: normalized.slice(0, 120),
        remediation: "External data exfiltration or reverse shells are strictly prohibited.",
      });
      break;
    }
  }

  // 5. Evaluate against Mandate Permissions
  if (isWriteAttempt && !mandate.allowWrite) {
    violations.push({
      signature: "S3",
      type: "OUT_OF_SCOPE_MUTATION",
      severity: "HIGH",
      description: "Filesystem write / redirection detected under a read-only mandate",
      evidence: normalized.slice(0, 120),
      remediation: "The active session mandate permits only read operations. Set allowWrite=true to authorize modifications.",
    });
  }

  if (isNetworkAttempt && !mandate.allowNetwork) {
    violations.push({
      signature: "S3",
      type: "UNAUTHORIZED_NETWORK_EGRESS",
      severity: "HIGH",
      description: "Outbound network command detected under a local-only mandate",
      evidence: normalized.slice(0, 120),
      remediation: "The active mandate forbids network egress. Set allowNetwork=true to enable internet access.",
    });
  }

  if (isSubshell && !mandate.allowSubshells) {
    violations.push({
      signature: "S3",
      type: "OBFUSCATION_BYPASS",
      severity: "MEDIUM",
      description: "Subshell execution ($() or backticks) detected when subshells are restricted",
      evidence: normalized.slice(0, 120),
      remediation: "Execute single-level direct commands without nested command substitution.",
    });
  }

  // Extract rough target path tokens for audit
  const targetPaths: string[] = [];
  const tokens = normalized.split(/\s+/);
  for (const token of tokens) {
    if (token.startsWith("/") || token.startsWith("./") || token.startsWith("../") || token.startsWith("~")) {
      targetPaths.push(token);
    }
  }

  return {
    isDestructive: violations.some((v) => v.severity === "CRITICAL"),
    isObfuscated: violations.some((v) => v.type === "OBFUSCATION_BYPASS"),
    isWriteAttempt,
    isNetworkAttempt,
    isSubshell,
    normalizedCommand: normalized,
    violations,
    targetPaths,
  };
}
