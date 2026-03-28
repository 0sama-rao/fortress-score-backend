import { promises as dns } from "dns";
import type { EmailSignals } from "../types/scoring.js";

export async function scanEmail(rootDomain: string): Promise<EmailSignals> {
  const signals: EmailSignals = {
    spfMissing: true,
    spfPermissive: false,
    dkimMissing: true,
    dmarcMissing: true,
    dmarcPolicyNone: false,
  };

  // 1. SPF — look for TXT record containing "v=spf1"
  try {
    const txtRecords = await dns.resolveTxt(rootDomain);
    const flat = txtRecords.map((r) => r.join(""));

    const spf = flat.find((r) => r.startsWith("v=spf1"));
    if (spf) {
      signals.spfMissing = false;
      // Check if overly permissive
      if (spf.includes("+all") || spf.includes("?all")) {
        signals.spfPermissive = true;
      }
    }
  } catch {
    // No TXT records — SPF missing stands
  }

  // 2. DKIM — check common selectors
  const dkimSelectors = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail"];
  for (const selector of dkimSelectors) {
    try {
      const records = await dns.resolveTxt(`${selector}._domainkey.${rootDomain}`);
      const flat = records.map((r) => r.join(""));
      if (flat.some((r) => r.includes("v=DKIM1") || r.includes("p="))) {
        signals.dkimMissing = false;
        break;
      }
    } catch {
      // This selector doesn't exist — try next
    }
  }

  // 3. DMARC — look for TXT record at _dmarc.domain
  try {
    const records = await dns.resolveTxt(`_dmarc.${rootDomain}`);
    const flat = records.map((r) => r.join(""));

    const dmarc = flat.find((r) => r.startsWith("v=DMARC1"));
    if (dmarc) {
      signals.dmarcMissing = false;
      // Check if policy is "none" (monitoring only, not enforced)
      if (dmarc.includes("p=none")) {
        signals.dmarcPolicyNone = true;
      }
    }
  } catch {
    // No DMARC record
  }

  return signals;
}
