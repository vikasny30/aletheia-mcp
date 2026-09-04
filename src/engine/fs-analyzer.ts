/**
 * Aletheia MCP Server: Filesystem & Path Boundary Guard
 * 
 * Target latency: <0.05ms
 * Validates: Path traversal, workspace boundary escape, sensitive credential access.
 * Fails closed: If allowedPaths is not explicitly set to ["*"], confines operations
 * to the specified paths or defaults to the active workspace [process.cwd()].
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
  
  // Resolve absolute path to properly check traversals
  const resolved = path.isAbsolute(candidatePath)
    ? path.normalize(candidatePath)
    : path.resolve(process.cwd(), candidatePath);
  const baseName = path.basename(resolved).toLowerCase();

  // 1. Check for Sensitive Files
  if (
    SENSITIVE_FILENAMES.has(baseName) ||
    resolved.includes("/.ssh/") ||
    resolved.includes("/.aws/") ||
    resolved.includes("/etc/shadow") ||
    resolved.includes("/etc/passwd") ||
    resolved.includes("/etc/sudoers")
  ) {
    violations.push({
      signature: "S3",
      type: "SENSITIVE_FILE_ACCESS",
      severity: "CRITICAL",
      description: `Access to protected secret / credential file '${baseName}'`,
      evidence: candidatePath,
      remediation: "Sensitive credential and configuration files are restricted from tool access.",
    });
  }

  // 2. Check Allowed Paths Boundary (Fail-closed: default to process.cwd() if empty)
  let isEscapingWorkspace = false;
  const effectiveAllowedRoots =
    mandate.allowedPaths && mandate.allowedPaths.length > 0
      ? mandate.allowedPaths
      : [process.cwd()];

  const isGloballyUnrestricted = effectiveAllowedRoots.includes("*");

  if (!isGloballyUnrestricted) {
    const isWithinAllowed = effectiveAllowedRoots.some((allowedRoot) => {
      const normalizedRoot = path.resolve(allowedRoot);
      const relative = path.relative(normalizedRoot, resolved);
      return !relative.startsWith("..") && !path.isAbsolute(relative);
    });

    if (!isWithinAllowed) {
      isEscapingWorkspace = true;
      violations.push({
        signature: "S3",
        type: "OUT_OF_SCOPE_MUTATION",
        severity: isWrite ? "HIGH" : "MEDIUM",
        description: `Path '${candidatePath}' (${resolved}) resides outside designated allowed workspace paths`,
        evidence: `Target: ${candidatePath}, Allowed: ${effectiveAllowedRoots.join(", ")}`,
        remediation: "Confine file operations strictly to the designated allowed workspace paths.",
      });
    }
  }

  // 3. Check Write authorization
  if (isWrite && !mandate.allowWrite) {
    violations.push({
      signature: "S3",
      type: "OUT_OF_SCOPE_MUTATION",
      severity: "HIGH",
      description: `Write operation on '${candidatePath}' rejected under read-only mandate`,
      evidence: candidatePath,
      remediation: "Active mandate permits read-only operations. Enabling allowWrite requires operator authorization (operatorSecret); agents cannot self-authorize write access.",
    });
  }

  return {
    isSensitive: violations.some((v) => v.type === "SENSITIVE_FILE_ACCESS"),
    isEscapingWorkspace,
    normalizedPath: resolved,
    violations,
  };
}
