import type { HeaderSignals } from "../types/scoring.js";

const HEADER_TIMEOUT = 10000;

export async function scanHeaders(hostname: string): Promise<HeaderSignals> {
  const signals: HeaderSignals = {
    missingHsts: true,
    missingCsp: true,
    missingXFrameOptions: true,
    missingXContentTypeOptions: true,
    missingXXssProtection: true,
    weakHstsMaxAge: false,
    weakCspPolicy: false,
    serverHeaderLeaksVersion: false,
  };

  try {
    const res = await fetch(`https://${hostname}`, {
      signal: AbortSignal.timeout(HEADER_TIMEOUT),
      redirect: "follow",
    });

    analyzeHeaders(res.headers, signals);
  } catch {
    // Host unreachable via HTTPS — try HTTP
    try {
      const res = await fetch(`http://${hostname}`, {
        signal: AbortSignal.timeout(HEADER_TIMEOUT),
        redirect: "follow",
      });

      // If we got here via HTTP, all security headers are effectively missing
      // Just check server header and XSS protection
      analyzeHeaders(res.headers, signals);
    } catch {
      // Host completely unreachable — return defaults (all missing = worst case)
    }
  }

  return signals;
}

function analyzeHeaders(headers: Headers, signals: HeaderSignals): void {
  // Strict-Transport-Security
  const hsts = headers.get("strict-transport-security");
  if (hsts) {
    signals.missingHsts = false;
    const maxAgeMatch = hsts.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1], 10);
      signals.weakHstsMaxAge = maxAge < 15552000; // 6 months
    }
  }

  // Content-Security-Policy
  const csp = headers.get("content-security-policy");
  if (csp) {
    signals.missingCsp = false;
    // Check for weak CSP: unsafe-inline or unsafe-eval or wildcard sources
    if (
      csp.includes("'unsafe-inline'") ||
      csp.includes("'unsafe-eval'") ||
      csp.includes("* ") ||
      csp.match(/default-src\s+\*/) ||
      csp.match(/script-src\s+[^;]*\*/)
    ) {
      signals.weakCspPolicy = true;
    }
  }

  // X-Frame-Options
  if (headers.get("x-frame-options")) {
    signals.missingXFrameOptions = false;
  }

  // X-Content-Type-Options
  if (headers.get("x-content-type-options")) {
    signals.missingXContentTypeOptions = false;
  }

  // X-XSS-Protection
  if (headers.get("x-xss-protection")) {
    signals.missingXXssProtection = false;
  }

  // Server header leaking version info
  const server = headers.get("server");
  if (server && /[\d.]+/.test(server)) {
    signals.serverHeaderLeaksVersion = true;
  }
}
