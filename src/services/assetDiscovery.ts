import { promises as dns } from "dns";
import { PrismaClient } from "@prisma/client";

const MAX_ASSETS = Number(process.env.MAX_ASSETS_PER_SCAN) || 20;

interface CrtShEntry {
  name_value: string;
}

export async function discoverAssets(
  prisma: PrismaClient,
  organizationId: string,
  rootDomain: string
): Promise<number> {
  const subdomains = new Set<string>();

  // Always include the root domain itself
  subdomains.add(rootDomain);

  // Fetch from crt.sh certificate transparency logs
  try {
    const url = `https://crt.sh/?q=%.${rootDomain}&output=json`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(15000),
      headers: { "User-Agent": "FortressScore/1.0" },
    });

    if (res.ok) {
      const entries: CrtShEntry[] = await res.json();

      for (const entry of entries) {
        // name_value can contain multiple newline-separated entries
        const names = entry.name_value.split("\n");
        for (const name of names) {
          const clean = name.trim().toLowerCase();
          // Skip wildcards and anything not under our root domain
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
  } catch {
    // crt.sh failed — continue with just the root domain
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
