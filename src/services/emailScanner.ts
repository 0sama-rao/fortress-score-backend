import { promises as dns } from "dns";
import type { EmailSignals } from "../types/scoring.js";

export async function scanEmail(rootDomain: string): Promise<EmailSignals> {
  const signals: EmailSignals = {
    spfMissing: true,
    spfPermissive: false,
    dkimMissing: true,
    dkimWeakKey: false,
    dmarcMissing: true,
    dmarcPolicyNone: false,
    dmarcMisconfigured: false,
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
      const dkimRecord = flat.find((r) => r.includes("v=DKIM1") || r.includes("p="));
      if (dkimRecord) {
        signals.dkimMissing = false;

        // Check DKIM key size — extract the public key and check its length
        // A base64-encoded 2048-bit RSA key is ~392 chars, 1024-bit is ~216 chars
        const keyMatch = dkimRecord.match(/p=([A-Za-z0-9+/=]+)/);
        if (keyMatch) {
          const keyBase64 = keyMatch[1];
          // 1024-bit key base64 is ~176 chars, 2048-bit is ~392 chars
          if (keyBase64.length < 300) {
            signals.dkimWeakKey = true;
          }
        }
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

      // Check for misconfiguration:
      // - Missing "p=" tag entirely
      // - rua/ruf pointing to external domain without proper authorization
      // - sp= (subdomain policy) set to none while p= is reject/quarantine
      const hasPolicy = /p=(none|quarantine|reject)/i.test(dmarc);
      if (!hasPolicy) {
        signals.dmarcMisconfigured = true;
      }

      // Check subdomain policy weaker than main policy
      const mainPolicy = dmarc.match(/;\s*p=(quarantine|reject)/i);
      const subPolicy = dmarc.match(/;\s*sp=none/i);
      if (mainPolicy && subPolicy) {
        signals.dmarcMisconfigured = true;
      }

      // Check if percentage is too low (pct < 100 means partial enforcement)
      const pctMatch = dmarc.match(/pct=(\d+)/i);
      if (pctMatch && parseInt(pctMatch[1], 10) < 100) {
        signals.dmarcMisconfigured = true;
      }
    }
  } catch {
    // No DMARC record
  }

  return signals;
}
