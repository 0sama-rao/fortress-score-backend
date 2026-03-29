export interface CategoryScore {
  score: number;
  weight: number;
}

export interface FortressScoreBreakdown {
  tls: CategoryScore;
  headers: CategoryScore;
  network: CategoryScore;
  email: CategoryScore;
}

export interface FortressScoreResponse {
  organizationId: string;
  fortressScore: number;
  breakdown: FortressScoreBreakdown;
  correlationBonus: number;
  scanId: string;
  scannedAt: Date;
}

export interface ScoreHistoryEntry {
  scanId: string;
  fortressScore: number;
  scannedAt: Date;
}

export interface ScoreHistoryResponse {
  organizationId: string;
  history: ScoreHistoryEntry[];
}

// Signal types — one interface per scanner category
export interface TLSSignals {
  noCertificate: boolean;
  certificateExpired: boolean;
  daysUntilExpiry: number;
  selfSigned: boolean;
  weakProtocol: boolean;
  weakCipher: boolean;
  wildcardCert: boolean;
  hostnameMismatch: boolean;
  noHttpsRedirect: boolean;
  longValidity: boolean;
  weakKeySize: "rsa1024" | "rsa2048" | "dsa2048" | "ecc224" | null;
  weakSignature: boolean;
  untrustedCA: boolean;
}

export interface HeaderSignals {
  missingHsts: boolean;
  missingCsp: boolean;
  missingXFrameOptions: boolean;
  missingXContentTypeOptions: boolean;
  missingXXssProtection: boolean;
  weakHstsMaxAge: boolean;
  weakCspPolicy: boolean;
  serverHeaderLeaksVersion: boolean;
}

export interface NetworkSignals {
  openPorts: number[];
  criticalPortsOpen: number[];
  rdpExposed: boolean;
  sshExposed: boolean;
  telnetOpen: boolean;
  ftpOpen: boolean;
  smbExposed: boolean;
  dbPortsExposed: boolean;
  exposureFactor: number;
}

export interface EmailSignals {
  spfMissing: boolean;
  spfPermissive: boolean;
  dkimMissing: boolean;
  dkimWeakKey: boolean;
  dmarcMissing: boolean;
  dmarcPolicyNone: boolean;
  dmarcMisconfigured: boolean;
}
