/**
 * Aletheia MCP Server: High-Performance Bash & Shell Lexical / Pattern Analyzer
 * 
 * Target latency: <0.1ms
 * Features:
 * - Multi-stage token unquoting (quote-split & backslash-split neutralization)
 * - Environment variable assignment resolution (X=rm; $X -rf /)
 * - Generalized fork-bomb detection (any function name)
 * - Interpreter escape hatch interception (python -c, node -e, perl, ruby, php, sh)
 * - SetUID / privilege escalation detection (chmod u+s, chmod 4755, sudo, su)
 * - File elimination tools (find -delete, shred, rsync --delete)
 * - De-obfuscation (base64, openssl enc, xxd -r, subshells, pipe-to-sh)
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
    pattern: /\brm\s+(-[a-z]{0,10}[rf][a-z]{0,10}\s+)+(\/+|\/\*|~\/?|\$HOME\/?|(\.\.|\.)\/?|\*|\.\/\*|\/tmp\/\*|\/etc\/?|\/usr\/?)(?![\w\-\/])/i,
    description: "Unbounded filesystem recursive delete (rm -rf root / home / wildcard)",
    type: "DESTRUCTIVE_FS_COMMAND",
  },
  {
    pattern: /\brm\s+-[a-z]{0,10}[rf][a-z]{0,10}\s+(\/+|\/\*|~\/?|\*|\.|\/etc\/?|\/usr\/?)(?![\w\-\/])/i,
    description: "Recursive delete of root, wildcard, or home",
    type: "DESTRUCTIVE_FS_COMMAND",
  },
  {
    pattern: /\bfind\s+[^;&|`]*(-[a-z]{0,8}delete|-exec\s+rm)\b/i,
    description: "Find utility with delete action or exec rm",
    type: "DESTRUCTIVE_FS_COMMAND",
  },
  {
    pattern: /\b(mkfs(\.[a-z0-9]+)?|dd\s+if=\S+\s+of=\/dev\/(sd[a-z]|nvme\d|disk\d)|fdisk|parted)\b/i,
    description: "Raw disk manipulation or partition formatting tool",
    type: "DESTRUCTIVE_FS_COMMAND",
  },
  {
    pattern: /\bgit\s+(reset\s+--hard|clean\s+-[a-z]{0,8}f[a-z]{0,8}|push\s+-[a-z]{0,8}f[a-z]{0,8}|push\s+--force)\b/i,
    description: "Destructive git operation (hard reset, forced clean, or force push)",
    type: "DESTRUCTIVE_FS_COMMAND",
  },
  {
    // Generalized fork bomb: any function calling itself piped into itself in background
    pattern: /\b([a-zA-Z0-9_]+)\s*\(\)\s*\{[^}]*\b\1\s*\|\s*\1\s*&[^}]*\}\s*;\s*\1\b/i,
    description: "Fork bomb process saturation sequence",
    type: "SYSTEM_STABILITY_THREAT",
  },
  {
    pattern: /(:(){ :\|:& };:|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:)/,
    description: "Classic fork bomb process saturation sequence",
    type: "SYSTEM_STABILITY_THREAT",
  },
  {
    pattern: /\b(shutdown|reboot|poweroff|halt|init\s+0)\b/i,
    description: "System shutdown / reboot termination instruction",
    type: "SYSTEM_STABILITY_THREAT",
  },
  {
    pattern: /\bchmod\s+(-[a-z]{0,8}R[a-z]{0,8}\s+)?(777|0777|a\+rwx)\s+(\/+|\/\*|~\/?|\$HOME\/?|\.\.?\/?)(?![\w\-\/])/i,
    description: "Broad global permission relaxation (chmod 777 on sensitive root)",
    type: "PRIVILEGE_ESCALATION",
  },
  {
    // SetUID / SetGID escalation: chmod u+s, chmod +s, chmod 4755
    pattern: /\bchmod\s+[^;&|`]*(\+[a-z]{0,8}s|[0-7]?[4-7][0-7]{3}|u\+s|g\+s)\b/i,
    description: "SetUID / SetGID permission elevation attempt",
    type: "PRIVILEGE_ESCALATION",
  },
  {
    pattern: /\b(sudo|su\s+-|doas)\b/i,
    description: "Privilege escalation attempt (sudo/su/doas)",
    type: "PRIVILEGE_ESCALATION",
  },
  {
    pattern: /\bshred\s+(-[a-z]{0,8}[ufrz]|--remove|--zero)\b/i,
    description: "Shred secure file destruction invocation",
    type: "DESTRUCTIVE_FS_COMMAND",
  },
  {
    pattern: /\brsync\s+[^;&|`]*--delete\b/i,
    description: "Rsync destructive mirror deletion flag (--delete)",
    type: "DESTRUCTIVE_FS_COMMAND",
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
    // base64, openssl enc, xxd -r piped to shell
    pattern: /(echo\s+[A-Za-z0-9+/=]{8,}\s*\|\s*)?(base64\s+(-d|--decode)|openssl\s+(enc\s+)?-base64\s+-d|xxd\s+-r)\s*\|\s*(ba|z)?sh/i,
    description: "Encoded string or cipher payload piped directly into execution shell",
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

// Interpreter escape hatch patterns: python -c "...", node -e "...", etc.
const INTERPRETER_PATTERNS = [
  {
    runtime: "python",
    pattern: /\b(python[23]?|pypy[23]?)\s+(-[a-zA-Z0-9]*c|--command)\s+([\x27"])([\s\S]*?)\3/i,
  },
  {
    runtime: "node",
    pattern: /\b(node|nodejs)\s+(-[a-zA-Z0-9]*e|--eval)\s+([\x27"])([\s\S]*?)\3/i,
  },
  {
    runtime: "perl",
    pattern: /\bperl\s+(-[a-zA-Z0-9]*e)\s+([\x27"])([\s\S]*?)\3/i,
  },
  {
    runtime: "ruby",
    pattern: /\bruby\s+(-[a-zA-Z0-9]*e)\s+([\x27"])([\s\S]*?)\3/i,
  },
  {
    runtime: "php",
    pattern: /\bphp\s+(-[a-zA-Z0-9]*r)\s+([\x27"])([\s\S]*?)\3/i,
  },
  {
    runtime: "shell",
    pattern: /\b(ba|z)?sh\s+(-[a-zA-Z0-9]*c)\s+([\x27"])([\s\S]*?)\3/i,
  },
];

// Dangerous functions inside interpreter scripts
const DANGEROUS_INTERPRETER_CALLS = [
  { pattern: /\b(os\.)?system\s*\(/i, description: "System shell execution (.system)" },
  { pattern: /\b(os\.)?popen\s*\(/i, description: "System shell pipe (.popen)" },
  { pattern: /\bfrom\s+os\s+import\s+[^;]*(\*|\b(system|popen|exec|spawn)\b)/i, description: "OS module shell execution import (from os import)" },
  { pattern: /\bfrom\s+subprocess\s+import\b/i, description: "Subprocess module execution import (from subprocess import)" },
  { pattern: /__import__\s*\(['"](os|subprocess)['"]\)/i, description: "Dynamic OS/subprocess module import (__import__)" },
  { pattern: /importlib/i, description: "Dynamic module import (importlib)" },
  { pattern: /subprocess\.(run|Popen|call|check_output)\s*\(/i, description: "Python subprocess execution" },
  { pattern: /shutil\.rmtree\s*\(/i, description: "Python recursive filesystem wipe (shutil.rmtree)" },
  { pattern: /child_process/i, description: "Node.js child_process invocation" },
  { pattern: /fs\.(rmSync|rmdirSync|unlinkSync|rm)\s*\(/i, description: "Node.js fs file/directory deletion" },
  { pattern: /(execSync|spawnSync)\s*\(/i, description: "Node.js synchronous process execution" },
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
 * Normalizes command text by:
 * 1. Stripping null bytes.
 * 2. Unescaping backslash-escaped characters (r\m -> rm).
 * 3. Token-level quote stripping for command and flag tokens (r'm' -> rm, 'r''m' -> rm).
 * 4. Resolving simple shell variable assignment indirection (X=rm; $X -rf /).
 */
export function normalizeCommand(raw: string): string {
  let cleaned = raw.trim().replace(/\0/g, "");

  // 1. Substitute shell $IFS word-splitting primitive ($IFS, ${IFS}) with a space
  // Also handle positional disambiguators like $IFS$9, $IFS$1, ${IFS}$9
  cleaned = cleaned.replace(/\$(?:IFS\b|\{IFS\})(?:\$[0-9*@#?!\-])*/g, " ");

  // 2. Expand brace expansions: e.g. /{etc,usr,home} -> /etc /usr /home or /{etc} -> /etc
  cleaned = cleaned.replace(/(\S*)\{([^{}\s]+)\}(\S*)/g, (_match, prefix, inner, suffix) => {
    const items = inner.split(",");
    return items.map((item: string) => `${prefix}${item.trim()}${suffix}`).join(" ");
  });

  // 3. Unescape backslashes before characters (e.g. \r\m -> rm)
  cleaned = cleaned.replace(/\\([a-zA-Z0-9_.\-\/])/g, "$1");

  // 4. Token-level quote stripping: within whitespace-delimited tokens, remove internal quotes
  cleaned = cleaned.replace(/\S+/g, (word) => {
    // If the word contains quotes, strip single and double quotes to form canonical word
    return word.replace(/['"]/g, "");
  });

  // 5. Resolve variable assignments: X=rm; $X -rf /
  const varMap: Record<string, string> = {};
  const assignRegex = /(?:export\s+)?([a-zA-Z_][a-zA-Z0-9_]*)=([^\s;]+)/g;
  let m: RegExpExecArray | null;
  while ((m = assignRegex.exec(cleaned)) !== null) {
    if (m[1] && m[2]) {
      varMap[m[1]] = m[2];
    }
  }

  for (const [varName, varVal] of Object.entries(varMap)) {
    cleaned = cleaned.replace(new RegExp(`\\$${varName}\\b`, "g"), varVal);
    cleaned = cleaned.replace(new RegExp(`\\$\\{${varName}\\}`, "g"), varVal);
  }

  // Collapse whitespace
  cleaned = cleaned.replace(/\s+/g, " ");
  return cleaned;
}

/**
 * Attempts to decode base64 payloads to inspect inner payload
 */
export function extractAndDecodeBase64(command: string): string | null {
  const b64Match =
    command.match(/base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh/i) ||
    command.match(/echo\s+([A-Za-z0-9+/=]{8,})\s*\|\s*base64/i) ||
    command.match(/openssl\s+(enc\s+)?-base64\s+-d\s*\|\s*(ba|z)?sh/i);

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
 * High-speed deterministic Bash safety analysis (<0.1ms)
 */
export function analyzeBashCommand(rawCommand: string, mandate: Mandate): BashAnalysis {
  const normalized = normalizeCommand(rawCommand);
  const violations: Violation[] = [];

  const isWriteAttempt = MUTATION_PATTERNS.some((p) => p.test(normalized));
  const isNetworkAttempt = NETWORK_COMMANDS.test(normalized);
  const isSubshell = /(`|\$\()/.test(normalized);

  // 1. Check Interpreter Escape Hatches (python -c, node -e, etc.)
  for (const interp of INTERPRETER_PATTERNS) {
    const match = rawCommand.match(interp.pattern);
    if (match) {
      const scriptBody = match[4];
      // Normalize string concatenations and implicit string literals inside script body
      // to defeat string-fragmentation evasions: 'r'+'m' -> 'rm', "r" + "m" -> "rm", 'r' 'm' -> 'rm'
      const normalizedScript = scriptBody
        .replace(/['"]\s*\+\s*['"]/g, "")
        .replace(/['"][ \t]+['"]/g, "");

      // Check for dangerous interpreter function calls in both raw and normalized script
      for (const danger of DANGEROUS_INTERPRETER_CALLS) {
        if (danger.pattern.test(scriptBody) || danger.pattern.test(normalizedScript)) {
          violations.push({
            signature: "S3",
            type: "INTERPRETER_ESCAPE_EXECUTION",
            severity: "CRITICAL",
            description: `Interpreter execution escape detected (${interp.runtime}): ${danger.description}`,
            evidence: rawCommand.slice(0, 140),
            remediation: "Execute explicit commands directly rather than hiding logic inside interpreter eval one-liners.",
          });
          break;
        }
      }

      // Recursively extract all unique quoted strings from both raw and normalized script body and analyze each
      const candidateStrings = new Set<string>();
      for (const m of scriptBody.matchAll(/['"]([^'"]+)['"]/g)) {
        candidateStrings.add(m[1]);
      }
      for (const m of normalizedScript.matchAll(/['"]([^'"]+)['"]/g)) {
        candidateStrings.add(m[1]);
      }

      for (const innerStr of candidateStrings) {
        if (innerStr.trim().length > 1) {
          const innerAnalysis = analyzeBashCommand(innerStr, mandate);
          for (const v of innerAnalysis.violations) {
            violations.push({
              ...v,
              description: `Interpreter payload violation: ${v.description}`,
            });
          }
        }
      }
    }
  }

  // 2. Check Obfuscation & Evasion Patterns
  for (const { pattern, description } of OBFUSCATION_PATTERNS) {
    if (pattern.test(rawCommand) || pattern.test(normalized)) {
      violations.push({
        signature: "S3",
        type: "OBFUSCATION_BYPASS",
        severity: "CRITICAL",
        description,
        evidence: rawCommand.slice(0, 120),
        remediation: "Execute explicit, transparent commands without piping encoded strings or dynamic eval.",
      });
      break;
    }
  }

  // Also inspect inside decoded base64 if present
  const decodedPayload = extractAndDecodeBase64(rawCommand);
  if (decodedPayload) {
    violations.push({
      signature: "S3",
      type: "OBFUSCATION_BYPASS",
      severity: "CRITICAL",
      description: `Hidden encoded payload detected: "${decodedPayload.slice(0, 80)}"`,
      evidence: rawCommand.slice(0, 100),
      remediation: "Disclose all commands transparently in plaintext.",
    });

    // Recursively check decoded payload
    const decodedAnalysis = analyzeBashCommand(decodedPayload, mandate);
    for (const v of decodedAnalysis.violations) {
      violations.push({
        ...v,
        description: `Decoded payload violation: ${v.description}`,
      });
    }
  }

  // 3. Check Destructive Signatures (Checked against normalized command)
  for (const { pattern, description, type } of DESTRUCTIVE_SIGNATURES) {
    if (pattern.test(normalized) || pattern.test(rawCommand)) {
      violations.push({
        signature: "S3",
        type,
        severity: "CRITICAL",
        description,
        evidence: rawCommand.slice(0, 120),
        remediation: "Destructive commands that erase files, partitions, or system states are blocked.",
      });
    }
  }

  // 4. Check Credential & Sensitive Path Access
  for (const pattern of SENSITIVE_PATH_PATTERNS) {
    if (pattern.test(normalized) || pattern.test(rawCommand)) {
      violations.push({
        signature: "S3",
        type: "SENSITIVE_FILE_ACCESS",
        severity: "HIGH",
        description: "Attempted read or access to credentials, SSH keys, or OS sensitive secrets",
        evidence: rawCommand.slice(0, 120),
        remediation: "Do not access .env, private keys, cloud tokens, or /etc secrets.",
      });
      break;
    }
  }

  // 5. Check Exfiltration Signatures
  for (const { pattern, description } of EXFILTRATION_PATTERNS) {
    if (pattern.test(normalized) || pattern.test(rawCommand)) {
      violations.push({
        signature: "S3",
        type: "CREDENTIAL_EXFILTRATION",
        severity: "CRITICAL",
        description,
        evidence: rawCommand.slice(0, 120),
        remediation: "External data exfiltration or reverse shells are strictly prohibited.",
      });
      break;
    }
  }

  // 6. Evaluate against Mandate Permissions
  if (isWriteAttempt && !mandate.allowWrite) {
    violations.push({
      signature: "S3",
      type: "OUT_OF_SCOPE_MUTATION",
      severity: "HIGH",
      description: "Filesystem write / redirection detected under a read-only mandate",
      evidence: rawCommand.slice(0, 120),
      remediation: "The active session mandate permits only read operations. Enabling allowWrite requires operator authorization (operatorSecret); agents cannot self-authorize write access.",
    });
  }

  if (isNetworkAttempt && !mandate.allowNetwork) {
    violations.push({
      signature: "S3",
      type: "UNAUTHORIZED_NETWORK_EGRESS",
      severity: "HIGH",
      description: "Outbound network command detected under a local-only mandate",
      evidence: rawCommand.slice(0, 120),
      remediation: "The active mandate forbids network egress. Enabling allowNetwork requires operator authorization (operatorSecret); agents cannot self-authorize network access.",
    });
  }

  if (isSubshell && !mandate.allowSubshells) {
    violations.push({
      signature: "S3",
      type: "OBFUSCATION_BYPASS",
      severity: "MEDIUM",
      description: "Subshell execution ($() or backticks) detected when subshells are restricted",
      evidence: rawCommand.slice(0, 120),
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
