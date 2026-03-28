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
  {
    name: "RDP exposed + weak TLS",
    bonus: 15,
    check: (s) => anyNetwork(s.network, "rdpExposed") && anyTLS(s.tls, "weakProtocol"),
  },
  {
    name: "No SPF + No DMARC",
    bonus: 20,
    check: (s) => s.email.spfMissing && s.email.dmarcMissing,
  },
  {
    name: "Expired certificate + missing HSTS",
    bonus: 10,
    check: (s) => anyTLS(s.tls, "certificateExpired") && anyHeaders(s.headers, "missingHsts"),
  },
  {
    name: "Wildcard cert + weak cipher",
    bonus: 10,
    check: (s) => anyTLS(s.tls, "wildcardCert") && anyTLS(s.tls, "weakCipher"),
  },
  {
    name: "SSH exposed + weak key/protocol",
    bonus: 20,
    check: (s) => anyNetwork(s.network, "sshExposed") && anyTLS(s.tls, "weakProtocol"),
  },
  {
    name: "Database exposed + no TLS",
    bonus: 15,
    check: (s) => anyNetwork(s.network, "dbPortsExposed") && anyTLS(s.tls, "noCertificate"),
  },
  {
    name: "Telnet open + missing CSP",
    bonus: 10,
    check: (s) => anyNetwork(s.network, "telnetOpen") && anyHeaders(s.headers, "missingCsp"),
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
