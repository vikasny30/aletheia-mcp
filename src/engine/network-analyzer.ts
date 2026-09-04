/**
 * Aletheia MCP Server: Network & SSRF Egress Guard
 * 
 * Target latency: <0.05ms
 * Validates: SSRF, Cloud Metadata access (AWS/GCP/Azure), private network probing,
 * and unauthorized internet connectivity under local-only mandates.
 */

import { Violation, Mandate } from "./types.js";

const SSRF_HOST_PATTERNS = [
  // AWS / Cloud Metadata service
  /169\.254\.169\.254/,
  /metadata\.google\.internal/i,
  /169\.254\.170\.2/, // ECS task metadata
  // Loopback & Private subnets
  /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1)$/i,
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
];

export interface NetworkAnalysis {
  isSSRF: boolean;
  violations: Violation[];
}

export function analyzeUrl(candidateUrl: string, mandate: Mandate): NetworkAnalysis {
  const violations: Violation[] = [];

  try {
    const parsed = new URL(candidateUrl);
    const hostname = parsed.hostname;

    // 1. Check for SSRF & Metadata Endpoints
    const isSSRF = SSRF_HOST_PATTERNS.some((pattern) => pattern.test(hostname));
    if (isSSRF) {
      violations.push({
        signature: "S3",
        type: "UNAUTHORIZED_NETWORK_EGRESS",
        severity: "CRITICAL",
        description: `Blocked attempt to access private loopback, local subnet, or cloud metadata (${hostname})`,
        evidence: candidateUrl,
        remediation: "Requests to private networks and cloud metadata instances are prohibited to prevent SSRF credential leaks.",
      });
    }

    // 2. Check Mandate Network Permission
    if (!mandate.allowNetwork) {
      violations.push({
        signature: "S3",
        type: "UNAUTHORIZED_NETWORK_EGRESS",
        severity: "HIGH",
        description: "Network request rejected under local-only mandate",
        evidence: candidateUrl,
        remediation: "The active session mandate permits offline operation only. Set allowNetwork=true to authorize external HTTP requests.",
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
