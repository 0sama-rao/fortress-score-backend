import type {
  TLSSignals,
  HeaderSignals,
  NetworkSignals,
  EmailSignals,
  FortressScoreBreakdown,
} from "../types/scoring.js";
import { computeCorrelationBonus } from "./correlationEngine.js";

// ─────────────────────────────────────────
// Signal weights — transparent & auditable
// ─────────────────────────────────────────

export const TLS_WEIGHTS = {
  noCertificate: 100,
  certificateExpired: 50,
  selfSigned: 40,
  hostnameMismatch: 40,
  weakProtocol: 30,
  weakCipher: 25,
  wildcardCert: 10,
} as const;

export const HEADER_WEIGHTS = {
  missingCsp: 30,
  missingHsts: 25,
  missingXFrameOptions: 10,
  missingXContentTypeOptions: 10,
  weakHstsMaxAge: 10,
  serverHeaderLeaksVersion: 5,
} as const;

export const NETWORK_WEIGHTS = {
  telnetOpen: 70,
  dbPortsExposed: 70,
  rdpExposed: 60,
  sshExposed: 40,
} as const;

export const EMAIL_WEIGHTS = {
  dmarcMissing: 60,
  spfPermissive: 60,
  spfMissing: 50,
  dkimMissing: 40,
  dmarcPolicyNone: 30,
} as const;

// Max possible score per category (sum of all weights)
const MAX_TLS = Object.values(TLS_WEIGHTS).reduce((a, b) => a + b, 0);
const MAX_HEADERS = Object.values(HEADER_WEIGHTS).reduce((a, b) => a + b, 0);
const MAX_NETWORK = Object.values(NETWORK_WEIGHTS).reduce((a, b) => a + b, 0);
const MAX_EMAIL = Object.values(EMAIL_WEIGHTS).reduce((a, b) => a + b, 0);

// Category weights in overall score
const CATEGORY_WEIGHTS = {
  tls: 0.30,
  headers: 0.30,
  network: 0.20,
  email: 0.20,
} as const;

// ─────────────────────────────────────────
// Per-category scoring
// ─────────────────────────────────────────

export function scoreTLS(signals: TLSSignals): number {
  let risk = 0;
  if (signals.noCertificate) risk += TLS_WEIGHTS.noCertificate;
  if (signals.certificateExpired) risk += TLS_WEIGHTS.certificateExpired;
  if (signals.selfSigned) risk += TLS_WEIGHTS.selfSigned;
  if (signals.hostnameMismatch) risk += TLS_WEIGHTS.hostnameMismatch;
  if (signals.weakProtocol) risk += TLS_WEIGHTS.weakProtocol;
  if (signals.weakCipher) risk += TLS_WEIGHTS.weakCipher;
  if (signals.wildcardCert) risk += TLS_WEIGHTS.wildcardCert;
  return Math.min(100, (risk / MAX_TLS) * 100);
}

export function scoreHeaders(signals: HeaderSignals): number {
  let risk = 0;
  if (signals.missingCsp) risk += HEADER_WEIGHTS.missingCsp;
  if (signals.missingHsts) risk += HEADER_WEIGHTS.missingHsts;
  if (signals.missingXFrameOptions) risk += HEADER_WEIGHTS.missingXFrameOptions;
  if (signals.missingXContentTypeOptions) risk += HEADER_WEIGHTS.missingXContentTypeOptions;
  if (signals.weakHstsMaxAge) risk += HEADER_WEIGHTS.weakHstsMaxAge;
  if (signals.serverHeaderLeaksVersion) risk += HEADER_WEIGHTS.serverHeaderLeaksVersion;
  return Math.min(100, (risk / MAX_HEADERS) * 100);
}

export function scoreNetwork(signals: NetworkSignals): number {
  let risk = 0;
  if (signals.telnetOpen) risk += NETWORK_WEIGHTS.telnetOpen;
  if (signals.dbPortsExposed) risk += NETWORK_WEIGHTS.dbPortsExposed;
  if (signals.rdpExposed) risk += NETWORK_WEIGHTS.rdpExposed;
  if (signals.sshExposed) risk += NETWORK_WEIGHTS.sshExposed;
  return Math.min(100, (risk / MAX_NETWORK) * 100);
}

export function scoreEmail(signals: EmailSignals): number {
  let risk = 0;
  if (signals.dmarcMissing) risk += EMAIL_WEIGHTS.dmarcMissing;
  if (signals.spfPermissive) risk += EMAIL_WEIGHTS.spfPermissive;
  if (signals.spfMissing) risk += EMAIL_WEIGHTS.spfMissing;
  if (signals.dkimMissing) risk += EMAIL_WEIGHTS.dkimMissing;
  if (signals.dmarcPolicyNone) risk += EMAIL_WEIGHTS.dmarcPolicyNone;
  return Math.min(100, (risk / MAX_EMAIL) * 100);
}

// ─────────────────────────────────────────
// Overall Fortress Score
// ─────────────────────────────────────────

export interface ScanScores {
  fortressScore: number;
  tlsScore: number;
  headersScore: number;
  networkScore: number;
  emailScore: number;
  correlationBonus: number;
  breakdown: FortressScoreBreakdown;
}

export function computeFortressScore(
  tlsSignalsArr: TLSSignals[],
  headerSignalsArr: HeaderSignals[],
  networkSignalsArr: NetworkSignals[],
  emailSignals: EmailSignals
): ScanScores {
  // Average across all assets for TLS, headers, network
  const tlsScore = average(tlsSignalsArr.map(scoreTLS));
  const headersScore = average(headerSignalsArr.map(scoreHeaders));
  const networkScore = average(networkSignalsArr.map(scoreNetwork));
  const emailScore = scoreEmail(emailSignals);

  // Compute correlation bonus from all signals
  const allSignals = {
    tls: tlsSignalsArr,
    headers: headerSignalsArr,
    network: networkSignalsArr,
    email: emailSignals,
  };
  const correlationBonus = computeCorrelationBonus(allSignals);

  // Weighted sum + correlation
  const base =
    tlsScore * CATEGORY_WEIGHTS.tls +
    headersScore * CATEGORY_WEIGHTS.headers +
    networkScore * CATEGORY_WEIGHTS.network +
    emailScore * CATEGORY_WEIGHTS.email;

  const fortressScore = Math.min(100, Math.round(base + correlationBonus));

  return {
    fortressScore,
    tlsScore: Math.round(tlsScore),
    headersScore: Math.round(headersScore),
    networkScore: Math.round(networkScore),
    emailScore: Math.round(emailScore),
    correlationBonus,
    breakdown: {
      tls: { score: Math.round(tlsScore), weight: CATEGORY_WEIGHTS.tls },
      headers: { score: Math.round(headersScore), weight: CATEGORY_WEIGHTS.headers },
      network: { score: Math.round(networkScore), weight: CATEGORY_WEIGHTS.network },
      email: { score: Math.round(emailScore), weight: CATEGORY_WEIGHTS.email },
    },
  };
}

function average(arr: number[]): number {
  if (arr.length === 0) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}
