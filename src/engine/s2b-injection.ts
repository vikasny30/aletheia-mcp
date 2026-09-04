/**
 * Aletheia MCP Server: Signature S2b (Adversarial Input Exploitation) Filter
 * 
 * Target latency: <0.05ms
 * Detects: Injected prompt overrides, jailbreaks, role hijacking, and
 * instruction subversion embedded within tool call arguments.
 */

import { Violation } from "./types.js";

const INJECTION_PATTERNS = [
  {
    pattern: /\b(ignore|disregard|forget|override)\s+(all\s+)?((previous|prior|above|existing|system)\s+)?(instructions?|prompts?|rules?|mandates?|policies|guards?)\b/i,
    description: "System prompt / instruction override directive",
  },
  {
    pattern: /\byou\s+are\s+now\s+(in\s+)?(an?|the)?\s*(unrestricted|developer|jailbreak|dan|stan|god|unfiltered|evil|anarchist|uncensored|liberated|unlocked|maximum)(\s+[a-z0-9_-]+){0,2}\s+(mode|role)\b/i,
    description: "Jailbreak mode adoption sequence",
  },
  {
    pattern: /\b(dan|jailbreak|unrestricted|god)\s+mode\b/i,
    description: "Jailbreak mode reference",
  },
  {
    pattern: /<\s*\/?\s*(system|assistant|im_start|im_end|rules|prompt_instructions)\s*>/i,
    description: "Adversarial chat template tag injection",
  },
  {
    pattern: /\[INSTRUCTION:\s*(BYPASS|IGNORE|OVERRIDE|ADMIN|UNRESTRICTED)\]/i,
    description: "Delimited control token injection sequence",
  },
  {
    pattern: /\b(as\s+(an\s+)?(ai|assistant)\s+without\s+(any\s+)?restrictions?|operating\s+without\s+rules|no\s+longer\s+bound\s+by)\b/i,
    description: "Explicit constraint repudiation claim",
  },
  {
    pattern: /\bfor\s+(debugging|testing|benchmark)\s+purposes?[,\s].{0,40}(skip|bypass|disable|ignore)\s+(all\s+)?(security|safety|auth|verification|audit)\b/i,
    description: "Purpose-clause safety bypass framing",
  },
];

function toInputString(raw: unknown): string {
  if (typeof raw === "string") return raw;
  if (Array.isArray(raw)) return raw.map((x) => String(x ?? "")).join(" ");
  if (raw !== null && typeof raw === "object") {
    try {
      return JSON.stringify(raw);
    } catch {
      return String(raw);
    }
  }
  if (raw !== undefined && raw !== null) return String(raw);
  return "";
}

/**
 * Strips zero-width and invisible control characters and applies NFKC Unicode canonical decomposition.
 */
export function normalizeAdversarialText(raw: string): string {
  return raw
    .replace(/[\u200B-\u200D\uFEFF\u00AD\u2060]/g, "")
    .normalize("NFKC");
}

export function analyzeAdversarialInput(rawInput: unknown): Violation[] {
  const violations: Violation[] = [];
  const text = toInputString(rawInput);
  if (!text || text.length < 5) return violations;

  const normalized = normalizeAdversarialText(text);

  for (const { pattern, description } of INJECTION_PATTERNS) {
    if (pattern.test(normalized) || pattern.test(text)) {
      violations.push({
        signature: "S2b",
        type: "PROMPT_INJECTION_PAYLOAD",
        severity: "CRITICAL",
        description,
        evidence: text.slice(0, 120),
        remediation: "Remove adversarial prompt injection constructs from tool arguments.",
      });
      break;
    }
  }

  return violations;
}
