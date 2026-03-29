import type {
  TLSSignals,
  HeaderSignals,
  NetworkSignals,
  EmailSignals,
} from "../types/scoring.js";

interface CorrelationRule {
  name: string;
  bonus: number;
  check: (signals: AllSignals) => boolean;
}

interface AllSignals {
  tls: TLSSignals[];
  headers: HeaderSignals[];
  network: NetworkSignals[];
  email: EmailSignals;
}

// Helper: check if ANY asset has a flag set
function anyTLS(signals: TLSSignals[], key: keyof TLSSignals): boolean {
  return signals.some((s) => Boolean(s[key]));
}

function anyNetwork(signals: NetworkSignals[], key: keyof NetworkSignals): boolean {
  return signals.some((s) => Boolean(s[key]));
}

function anyHeaders(signals: HeaderSignals[], key: keyof HeaderSignals): boolean {
  return signals.some((s) => Boolean(s[key]));
}

// ─────────────────────────────────────────
// Correlation rules — data-driven
// ─────────────────────────────────────────

const RULES: CorrelationRule[] = [
  // From spec: RDP exposed + weak TLS
  {
    name: "RDP exposed + weak TLS",
    bonus: 15,
    check: (s) => anyNetwork(s.network, "rdpExposed") && anyTLS(s.tls, "weakProtocol"),
  },
  // From spec: No SPF + No DMARC
  {
    name: "No SPF + No DMARC",
    bonus: 20,
    check: (s) => s.email.spfMissing && s.email.dmarcMissing,
  },
  // From spec: Weak TLS + Missing HSTS
  {
    name: "Weak TLS + Missing HSTS",
    bonus: 10,
    check: (s) => anyTLS(s.tls, "weakProtocol") && anyHeaders(s.headers, "missingHsts"),
  },
  // From spec: Expired certificate + missing HSTS
  {
    name: "Expired certificate + missing HSTS",
    bonus: 10,
    check: (s) => anyTLS(s.tls, "certificateExpired") && anyHeaders(s.headers, "missingHsts"),
  },
  // From spec: Wildcard cert + many subdomains (>10 assets)
  {
    name: "Wildcard cert + many subdomains",
    bonus: 15,
    check: (s) => anyTLS(s.tls, "wildcardCert") && s.tls.length > 10,
  },
  // From spec: Open SSH + weak key
  {
    name: "SSH exposed + weak key/protocol",
    bonus: 20,
    check: (s) => anyNetwork(s.network, "sshExposed") && (anyTLS(s.tls, "weakProtocol") || s.tls.some((t) => t.weakKeySize !== null)),
  },
  // From spec: No DMARC + active phishing domain (approximated by missing SPF + missing DKIM)
  {
    name: "No DMARC + No DKIM (phishing risk)",
    bonus: 30,
    check: (s) => s.email.dmarcMissing && s.email.dkimMissing,
  },
  // Wildcard cert + weak cipher
  {
    name: "Wildcard cert + weak cipher",
    bonus: 10,
    check: (s) => anyTLS(s.tls, "wildcardCert") && anyTLS(s.tls, "weakCipher"),
  },
  // Database exposed + no TLS
  {
    name: "Database exposed + no TLS",
    bonus: 15,
    check: (s) => anyNetwork(s.network, "dbPortsExposed") && anyTLS(s.tls, "noCertificate"),
  },
  // Telnet open + missing CSP
  {
    name: "Telnet open + missing CSP",
    bonus: 10,
    check: (s) => anyNetwork(s.network, "telnetOpen") && anyHeaders(s.headers, "missingCsp"),
  },
  // FTP open + no HTTPS redirect
  {
    name: "FTP open + no HTTPS redirect",
    bonus: 15,
    check: (s) => anyNetwork(s.network, "ftpOpen") && anyTLS(s.tls, "noHttpsRedirect"),
  },
];

export function computeCorrelationBonus(signals: AllSignals): number {
  let total = 0;
  for (const rule of RULES) {
    if (rule.check(signals)) {
      total += rule.bonus;
    }
  }
  return total;
}
