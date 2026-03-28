export type ScanStatus = "PENDING" | "RUNNING" | "COMPLETE" | "FAILED";
export type ScanCategory = "TLS" | "HEADERS" | "NETWORK" | "EMAIL";

export interface ScanResponse {
  id: string;
  organizationId: string;
  status: ScanStatus;
  fortressScore: number | null;
  tlsScore: number | null;
  headersScore: number | null;
  networkScore: number | null;
  emailScore: number | null;
  startedAt: Date;
  completedAt: Date | null;
}

export interface ScanResultResponse {
  id: string;
  scanId: string;
  assetId: string;
  assetValue: string;
  category: ScanCategory;
  riskScore: number;
  signals: Record<string, unknown>;
  scannedAt: Date;
}
