/**
 * Vulnerability Intelligence — adapted from ClearFeed's cveExtractor.
 * Uses CISA KEV (free, no key) to check if detected services have known exploited vulns.
 * Uses NVD API to look up CVEs by service CPE.
 */

// ── CISA KEV cache ──
interface KEVEntry {
  cveID: string;
  dateAdded: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  vendorProject: string;
  product: string;
  shortDescription: string;
}

let kevCache: KEVEntry[] | null = null;
let kevCacheTimestamp = 0;
const KEV_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

async function getKEVData(): Promise<KEVEntry[]> {
  if (kevCache && Date.now() - kevCacheTimestamp < KEV_CACHE_TTL) {
    return kevCache;
  }

  try {
    const response = await fetch(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      { signal: AbortSignal.timeout(30000) }
    );
    const data = (await response.json()) as { vulnerabilities: KEVEntry[] };
    kevCache = data.vulnerabilities || [];
    kevCacheTimestamp = Date.now();
    console.log(`[VulnIntel] KEV cache refreshed: ${kevCache.length} entries`);
    return kevCache;
  } catch (err) {
    console.error(`[VulnIntel] KEV fetch failed:`, err instanceof Error ? err.message : err);
    return kevCache ?? [];
  }
}

// ── Service-to-product mapping ──
// Maps detected services (from nmap/headers) to vendor/product names used in KEV
const SERVICE_MAP: Record<string, { vendor: string; product: string }[]> = {
  "SSH": [{ vendor: "openbsd", product: "openssh" }],
  "FTP": [{ vendor: "vsftpd_project", product: "vsftpd" }, { vendor: "pureftpd", product: "pure-ftpd" }],
  "RDP": [{ vendor: "microsoft", product: "remote_desktop" }, { vendor: "microsoft", product: "windows" }],
  "SMB": [{ vendor: "microsoft", product: "windows" }, { vendor: "samba", product: "samba" }],
  "MSSQL": [{ vendor: "microsoft", product: "sql_server" }],
  "MySQL": [{ vendor: "oracle", product: "mysql" }, { vendor: "mariadb", product: "mariadb" }],
  "PostgreSQL": [{ vendor: "postgresql", product: "postgresql" }],
  "Redis": [{ vendor: "redis", product: "redis" }],
  "MongoDB": [{ vendor: "mongodb", product: "mongodb" }],
  "Telnet": [{ vendor: "gnu", product: "inetutils" }],
  "Apache": [{ vendor: "apache", product: "http_server" }],
  "nginx": [{ vendor: "f5", product: "nginx" }],
  "IIS": [{ vendor: "microsoft", product: "internet_information_services" }],
};

export interface VulnIntelResult {
  totalKEVMatches: number;
  kevFindings: Array<{
    cveId: string;
    vendor: string;
    product: string;
    description: string;
    dateAdded: string;
    dueDate: string;
    ransomwareUse: boolean;
  }>;
  servicesChecked: string[];
}

/**
 * Check exposed services against CISA KEV to find known exploited vulnerabilities.
 * No API key needed — KEV is a free public JSON feed.
 */
export async function checkVulnIntel(
  exposedServices: string[],
  serverHeader?: string | null
): Promise<VulnIntelResult> {
  const result: VulnIntelResult = {
    totalKEVMatches: 0,
    kevFindings: [],
    servicesChecked: [],
  };

  // Build list of vendor/product pairs to check
  const productsToCheck: Array<{ vendor: string; product: string; service: string }> = [];

  for (const service of exposedServices) {
    const mappings = SERVICE_MAP[service];
    if (mappings) {
      for (const m of mappings) {
        productsToCheck.push({ ...m, service });
      }
      result.servicesChecked.push(service);
    }
  }

  // Check server header for web server identification
  if (serverHeader) {
    const lower = serverHeader.toLowerCase();
    if (lower.includes("apache")) {
      productsToCheck.push({ vendor: "apache", product: "http_server", service: "Apache" });
      result.servicesChecked.push("Apache");
    }
    if (lower.includes("nginx")) {
      productsToCheck.push({ vendor: "f5", product: "nginx", service: "nginx" });
      result.servicesChecked.push("nginx");
    }
    if (lower.includes("iis") || lower.includes("microsoft")) {
      productsToCheck.push({ vendor: "microsoft", product: "internet_information_services", service: "IIS" });
      result.servicesChecked.push("IIS");
    }
  }

  if (productsToCheck.length === 0) return result;

  // Fetch KEV data
  const kevEntries = await getKEVData();

  // Match exposed services against KEV entries
  for (const check of productsToCheck) {
    const matches = kevEntries.filter((kev) => {
      const kevVendor = kev.vendorProject.toLowerCase().replace(/\s+/g, "_");
      const kevProduct = kev.product.toLowerCase().replace(/\s+/g, "_");
      return (
        kevVendor.includes(check.vendor) ||
        check.vendor.includes(kevVendor) ||
        kevProduct.includes(check.product) ||
        check.product.includes(kevProduct)
      );
    });

    // Take the most recent 5 KEVs per service to avoid flooding
    const recent = matches
      .sort((a, b) => new Date(b.dateAdded).getTime() - new Date(a.dateAdded).getTime())
      .slice(0, 5);

    for (const kev of recent) {
      // Avoid duplicates
      if (!result.kevFindings.some((f) => f.cveId === kev.cveID)) {
        result.kevFindings.push({
          cveId: kev.cveID,
          vendor: kev.vendorProject,
          product: kev.product,
          description: kev.shortDescription || "",
          dateAdded: kev.dateAdded,
          dueDate: kev.dueDate,
          ransomwareUse: kev.knownRansomwareCampaignUse === "Known",
        });
      }
    }
  }

  result.totalKEVMatches = result.kevFindings.length;

  // Cap at 20 findings total
  result.kevFindings = result.kevFindings.slice(0, 20);

  return result;
}
