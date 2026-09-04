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
  ".git-credentials",
  ".gitconfig",
]);

export interface FsAnalysis {
  isSensitive: boolean;
  isEscapingWorkspace: boolean;
  normalizedPath: string;
  violations: Violation[];
}

function toPathString(raw: unknown): string {
  if (typeof raw === "string") return raw;
  if (Array.isArray(raw)) return raw.map((x) => String(x ?? "")).join("/");
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

export function analyzePath(candidatePathInput: unknown, mandate: Mandate, isWrite: boolean = false): FsAnalysis {
  const violations: Violation[] = [];
  const candidatePath = toPathString(candidatePathInput);

  // Safely URL-decode path to catch percent-encoded traversals and secret filenames
  let decodedPath = candidatePath;
  try {
    decodedPath = decodeURIComponent(candidatePath);
    if (decodedPath.includes("%")) {
      decodedPath = decodeURIComponent(decodedPath);
    }
  } catch {}
  
  // Resolve absolute path to properly check traversals
  const resolved = path.isAbsolute(decodedPath)
    ? path.normalize(decodedPath)
    : path.resolve(process.cwd(), decodedPath);
  const baseName = path.basename(resolved).toLowerCase();
  const rawResolved = path.isAbsolute(candidatePath)
    ? path.normalize(candidatePath)
    : path.resolve(process.cwd(), candidatePath);
  const rawBaseName = path.basename(rawResolved).toLowerCase();

  const isEnvFile =
    baseName === ".env" ||
    baseName.startsWith(".env.") ||
    rawBaseName === ".env" ||
    rawBaseName.startsWith(".env.");

  // 1. Check for Sensitive Files and Directories
  if (
    isEnvFile ||
    SENSITIVE_FILENAMES.has(baseName) ||
    SENSITIVE_FILENAMES.has(rawBaseName) ||
    resolved.includes("/.ssh/") ||
    resolved.includes("/.aws/") ||
    resolved.includes("/.kube/") ||
    resolved.includes("/.docker/") ||
    resolved.includes("/.gnupg/") ||
    resolved.includes("/etc/shadow") ||
    resolved.includes("/etc/passwd") ||
    resolved.includes("/etc/sudoers") ||
    rawResolved.includes("/.ssh/") ||
    rawResolved.includes("/.aws/") ||
    rawResolved.includes("/.kube/") ||
    rawResolved.includes("/.docker/") ||
    rawResolved.includes("/.gnupg/")
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
