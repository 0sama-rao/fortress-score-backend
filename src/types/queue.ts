export interface ScanJobPayload {
  scanId: string;
  organizationId: string;
  rootDomain: string;
}

export interface AssetScanJobPayload {
  scanId: string;
  assetId: string;
  assetValue: string;
  assetType: "DOMAIN" | "SUBDOMAIN" | "IP";
}
