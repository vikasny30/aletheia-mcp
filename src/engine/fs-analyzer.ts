/**
 * Aletheia MCP Server: Filesystem & Path Boundary Guard
 * 
 * Target latency: <0.05ms
 * Validates: Path traversal, workspace boundary escape, sensitive credential access.
 */

import path from "node:path";
import { Violation, Mandate } from "./types.js";

const SENSITIVE_FILENAMES = new Set([
  ".env",
  ".env.local",
  ".env.production",
  ".env.development",
  "id_rsa",
  "id_ed25519",
  "id_ecdsa",
  "id_dsa",
  "known_hosts",
  "authorized_keys",
  "credentials",
  "master.key",
  "service-account.json",
  "shadow",
  "passwd",
  "sudoers",
  ".npmrc",
  ".netrc",
]);

export interface FsAnalysis {
  isSensitive: boolean;
  isEscapingWorkspace: boolean;
  normalizedPath: string;
  violations: Violation[];
}

export function analyzePath(candidatePath: string, mandate: Mandate, isWrite: boolean = false): FsAnalysis {
  const violations: Violation[] = [];
  const normalized = path.normalize(candidatePath);
  const baseName = path.basename(normalized).toLowerCase();

  // 1. Check for Sensitive Files
  if (SENSITIVE_FILENAMES.has(baseName) || normalized.includes("/.ssh/") || normalized.includes("/.aws/")) {
    violations.push({
      signature: "S3",
      type: "SENSITIVE_FILE_ACCESS",
      severity: "CRITICAL",
      description: `Access to protected secret / credential file '${baseName}'`,
      evidence: normalized,
      remediation: "Sensitive credential and configuration files are restricted from tool access.",
    });
  }

  // 2. Check Allowed Paths Boundary (if configured in mandate)
  let isEscapingWorkspace = false;
  if (mandate.allowedPaths && mandate.allowedPaths.length > 0) {
    const isWithinAllowed = mandate.allowedPaths.some((allowedRoot) => {
      const normalizedRoot = path.normalize(allowedRoot);
      const relative = path.relative(normalizedRoot, normalized);
      return !relative.startsWith("..") && !path.isAbsolute(relative);
    });

    if (!isWithinAllowed) {
      isEscapingWorkspace = true;
      violations.push({
        signature: "S3",
        type: "OUT_OF_SCOPE_MUTATION",
        severity: isWrite ? "HIGH" : "MEDIUM",
        description: `Path '${normalized}' resides outside designated allowed workspace paths`,
        evidence: `Target: ${normalized}, Allowed: ${mandate.allowedPaths.join(", ")}`,
        remediation: "Confine file operations strictly to the designated allowed paths.",
      });
    }
  }

  // 3. Check Write authorization
  if (isWrite && !mandate.allowWrite) {
    violations.push({
      signature: "S3",
      type: "OUT_OF_SCOPE_MUTATION",
      severity: "HIGH",
      description: `Write operation on '${normalized}' rejected under read-only mandate`,
      evidence: normalized,
      remediation: "Active mandate does not permit write mutations. Update mandate with allowWrite=true to proceed.",
    });
  }

  return {
    isSensitive: violations.some((v) => v.type === "SENSITIVE_FILE_ACCESS"),
    isEscapingWorkspace,
    normalizedPath: normalized,
    violations,
  };
}
