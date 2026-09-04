/**
 * Aletheia MCP Server: Network & SSRF Egress Guard
 * 
 * Target latency: <0.05ms
 * Validates: SSRF, Cloud Metadata access (AWS/GCP/Azure), private network probing,
 * and unauthorized internet connectivity under local-only mandates.
 */

import { Violation, Mandate } from "./types.js";

const CLOUD_METADATA_PATTERNS = [
  /169\.254\.169\.254/,
  /metadata\.google\.internal/i,
  /169\.254\.170\.2/, // ECS task metadata
];

const LOOPBACK_PATTERNS = [
  /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1)$/i,
];

const PRIVATE_SUBNET_PATTERNS = [
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
];

export interface NetworkAnalysis {
  isSSRF: boolean;
  violations: Violation[];
}

/**
 * Normalizes hostnames by converting IPv4-mapped and IPv4-compatible IPv6 addresses
 * (e.g. `[::ffff:a9fe:a9fe]` or `[::ffff:169.254.169.254]`) to canonical dotted-decimal IPv4.
 */
export function normalizeHostname(raw: string): string {
  const clean = raw.replace(/^\[|\]$/g, "").toLowerCase();
  if (clean === "::" || clean === "0:0:0:0:0:0:0:0") {
    return "0.0.0.0";
  }
  if (clean === "::1" || clean === "0:0:0:0:0:0:0:1") {
    return "::1";
  }
  // Match IPv4-mapped (::ffff:xxxx:xxxx) or IPv4-compatible (::xxxx:xxxx) hex forms
  const hexMatch = clean.match(/^::(?:ffff:)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hexMatch) {
    const p1 = parseInt(hexMatch[1], 16);
    const p2 = parseInt(hexMatch[2], 16);
    return `${(p1 >> 8) & 0xff}.${p1 & 0xff}.${(p2 >> 8) & 0xff}.${p2 & 0xff}`;
  }
  // Match dotted-decimal trailing form (e.g. ::ffff:169.254.169.254)
  const dotMatch = clean.match(/^::(?:ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dotMatch) {
    return dotMatch[1];
  }
  return clean;
}

export function analyzeUrl(candidateUrl: string, mandate: Mandate): NetworkAnalysis {
  const violations: Violation[] = [];

  try {
    const parsed = new URL(candidateUrl);
    const hostname = parsed.hostname;
    const normalizedHostname = normalizeHostname(hostname);

    const isCloudMetadata = CLOUD_METADATA_PATTERNS.some((pattern) => pattern.test(normalizedHostname) || pattern.test(hostname));
    const isLoopback = LOOPBACK_PATTERNS.some((pattern) => pattern.test(normalizedHostname) || pattern.test(hostname));
    const isPrivateSubnet = PRIVATE_SUBNET_PATTERNS.some((pattern) => pattern.test(normalizedHostname) || pattern.test(hostname));
    const isSSRF = isCloudMetadata || isPrivateSubnet || isLoopback;

    // 1. Cloud metadata service: strictly prohibited under all mandates
    if (isCloudMetadata) {
      violations.push({
        signature: "S3",
        type: "UNAUTHORIZED_NETWORK_EGRESS",
        severity: "CRITICAL",
        description: `Blocked attempt to access cloud instance metadata (${hostname})`,
        evidence: candidateUrl,
        remediation: "Requests to cloud metadata endpoints are strictly prohibited to prevent credential exfiltration.",
      });
    }

    // 2. Private enterprise subnets: prohibited to prevent internal pivot/SSRF
    if (isPrivateSubnet) {
      violations.push({
        signature: "S3",
        type: "UNAUTHORIZED_NETWORK_EGRESS",
        severity: "CRITICAL",
        description: `Blocked attempt to probe private enterprise subnet (${hostname})`,
        evidence: candidateUrl,
        remediation: "Direct HTTP probing of private RFC1918 subnets is prohibited.",
      });
    }

    // 3. Local loopback services: allowed if allowLoopback=true, blocked by default
    if (isLoopback && !mandate.allowLoopback) {
      violations.push({
        signature: "S3",
        type: "UNAUTHORIZED_NETWORK_EGRESS",
        severity: "HIGH",
        description: `Blocked attempt to access local loopback service (${hostname}) without loopback authorization`,
        evidence: candidateUrl,
        remediation: "Requests to local dev services (localhost / 127.0.0.1) require allowLoopback=true in the mandate. Enabling this requires operator authorization (operatorSecret).",
      });
    }

    // 4. Check general outbound network permission (exempting authorized loopback)
    if (!mandate.allowNetwork && !(isLoopback && mandate.allowLoopback)) {
      violations.push({
        signature: "S3",
        type: "UNAUTHORIZED_NETWORK_EGRESS",
        severity: "HIGH",
        description: "External network request rejected under local-only mandate",
        evidence: candidateUrl,
        remediation: "The active session mandate permits offline operation only. Enabling allowNetwork requires operator authorization (operatorSecret); agents cannot self-authorize external network access.",
      });
    }

    return {
      isSSRF,
      violations,
    };
  } catch {
    // Malformed URL or non-URL string
    return {
      isSSRF: false,
      violations,
    };
  }
}
