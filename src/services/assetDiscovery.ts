import { promises as dns } from "dns";
import { PrismaClient } from "@prisma/client";

const MAX_ASSETS = Number(process.env.MAX_ASSETS_PER_SCAN) || 20;

interface CrtShEntry {
  name_value: string;
}

export interface ASNInfo {
  ip: string;
  asn: string;
  org: string;
  isp: string;
  country: string;
}

export async function discoverAssets(
  prisma: PrismaClient,
  organizationId: string,
  rootDomain: string
): Promise<number> {
  const subdomains = new Set<string>();

  // Always include the root domain itself
  subdomains.add(rootDomain);

  // Source 1: crt.sh certificate transparency logs
  try {
    const url = `https://crt.sh/?q=%.${rootDomain}&output=json`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(45000),
      headers: { "User-Agent": "FortressScore/1.0" },
    });

    if (res.ok) {
      const entries: CrtShEntry[] = await res.json();

      for (const entry of entries) {
        const names = entry.name_value.split("\n");
        for (const name of names) {
          const clean = name.trim().toLowerCase();
          if (
            clean &&
            !clean.startsWith("*") &&
            (clean === rootDomain || clean.endsWith(`.${rootDomain}`))
          ) {
            subdomains.add(clean);
          }
        }
      }
    }
    console.log(`[discovery] crt.sh returned ${subdomains.size - 1} subdomains for ${rootDomain}`);
  } catch (err) {
    console.log(`[discovery] crt.sh failed for ${rootDomain}: ${err instanceof Error ? err.message : "unknown"}`);
  }

  // Source 2: Fallback — HackerTarget API (free, no key, 100 queries/day)
  if (subdomains.size <= 1) {
    try {
      const res = await fetch(`https://api.hackertarget.com/hostsearch/?q=${rootDomain}`, {
        signal: AbortSignal.timeout(15000),
      });
      if (res.ok) {
        const text = await res.text();
        if (!text.startsWith("error")) {
          for (const line of text.split("\n")) {
            const hostname = line.split(",")[0]?.trim().toLowerCase();
            if (hostname && (hostname === rootDomain || hostname.endsWith(`.${rootDomain}`))) {
              subdomains.add(hostname);
            }
          }
        }
      }
      console.log(`[discovery] HackerTarget returned ${subdomains.size - 1} subdomains for ${rootDomain}`);
    } catch (err) {
      console.log(`[discovery] HackerTarget failed for ${rootDomain}: ${err instanceof Error ? err.message : "unknown"}`);
    }
  }

  // Source 3: Fallback — common subdomain brute-force via DNS
  if (subdomains.size <= 1) {
    console.log(`[discovery] Trying common subdomains for ${rootDomain}...`);
    const common = ["www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "blog", "dev",
      "staging", "api", "app", "admin", "portal", "vpn", "remote", "test", "m", "mobile",
      "shop", "store", "cdn", "media", "static", "assets", "docs", "support", "help"];
    for (const sub of common) {
      try {
        await dns.resolve(`${sub}.${rootDomain}`);
        subdomains.add(`${sub}.${rootDomain}`);
      } catch {
        // doesn't resolve
      }
    }
    console.log(`[discovery] DNS brute-force found ${subdomains.size - 1} subdomains for ${rootDomain}`);
  }

  // Resolve each to confirm it's live, cap at MAX_ASSETS
  const confirmed: string[] = [];
  for (const subdomain of subdomains) {
    if (confirmed.length >= MAX_ASSETS) break;

    try {
      await dns.resolve(subdomain);
      confirmed.push(subdomain);
    } catch {
      // Not resolvable — skip
    }
  }

  // Upsert assets into DB
  for (const value of confirmed) {
    const type = value === rootDomain ? "DOMAIN" : "SUBDOMAIN";
    await prisma.asset.upsert({
      where: { organizationId_value: { organizationId, value } },
      update: { discoveredAt: new Date() },
      create: { organizationId, type, value },
    });
  }

  return confirmed.length;
}

/**
 * ASN Lookup — resolve hostname to IP and get ASN/ISP/country info.
 * Uses free ip-api.com (no key needed, 45 requests/min).
 */
export async function lookupASN(hostname: string): Promise<ASNInfo | null> {
  try {
    // Resolve hostname to IP first
    const ips = await dns.resolve4(hostname);
    if (!ips || ips.length === 0) return null;
    const ip = ips[0];

    const res = await fetch(`http://ip-api.com/json/${ip}?fields=query,as,org,isp,country`, {
      signal: AbortSignal.timeout(5000),
    });

    if (!res.ok) return null;

    const data = (await res.json()) as {
      query: string;
      as: string;
      org: string;
      isp: string;
      country: string;
    };

    return {
      ip: data.query,
      asn: data.as,
      org: data.org,
      isp: data.isp,
      country: data.country,
    };
  } catch {
    return null;
  }
}

/**
 * Lookup ASN info for multiple assets (with rate limiting for ip-api free tier).
 */
export async function lookupASNForAssets(hostnames: string[]): Promise<Map<string, ASNInfo>> {
  const results = new Map<string, ASNInfo>();

  // ip-api allows 45 requests/min on free tier — limit to 5 assets
  for (const hostname of hostnames.slice(0, 5)) {
    const info = await lookupASN(hostname);
    if (info) {
      results.set(hostname, info);
    }
  }

  return results;
}
