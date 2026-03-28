export interface OrganizationResponse {
  id: string;
  userId: string;
  name: string;
  rootDomain: string;
  createdAt: Date;
}

export interface AssetResponse {
  id: string;
  organizationId: string;
  type: "DOMAIN" | "SUBDOMAIN" | "IP";
  value: string;
  discoveredAt: Date;
}
