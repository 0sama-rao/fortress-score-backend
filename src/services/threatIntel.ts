import { promises as dns } from "dns";

export interface ThreatIntelResult {
  hostname: string;
  ip: string | null;
  inDnsBlocklist: boolean;
  blocklists: string[];
  reverseRecordMismatch: boolean;
}

// DNS-based blocklists (free, no API key needed)
const DNS_BLOCKLISTS = [
  { zone: "zen.spamhaus.org", name: "Spamhaus" },
  { zone: "bl.spamcop.net", name: "SpamCop" },
  { zone: "b.barracudacentral.org", name: "Barracuda" },
  { zone: "dnsbl.sorbs.net", name: "SORBS" },
  { zone: "spam.dnsbl.sorbs.net", name: "SORBS Spam" },
];

export async function checkThreatIntel(hostname: string): Promise<ThreatIntelResult> {
  const result: ThreatIntelResult = {
    hostname,
    ip: null,
    inDnsBlocklist: false,
    blocklists: [],
    reverseRecordMismatch: false,
  };

  // Resolve hostname to IP
  try {
    const ips = await dns.resolve4(hostname);
    if (!ips || ips.length === 0) return result;
    result.ip = ips[0];
  } catch {
    return result;
  }

  const ip = result.ip!;
  const reversedIp = ip.split(".").reverse().join(".");

  // Check DNS blocklists in parallel
  const blocklistChecks = DNS_BLOCKLISTS.map(async (bl) => {
    try {
      const lookup = `${reversedIp}.${bl.zone}`;
      await dns.resolve4(lookup);
      // If it resolves, the IP is listed
      return bl.name;
    } catch {
      // Not listed — good
      return null;
    }
  });

  const blocklistResults = await Promise.allSettled(blocklistChecks);
  for (const r of blocklistResults) {
    if (r.status === "fulfilled" && r.value) {
      result.blocklists.push(r.value);
    }
  }
  result.inDnsBlocklist = result.blocklists.length > 0;

  // Check reverse DNS mismatch (forward-confirmed reverse DNS)
  try {
    const reverseNames = await dns.reverse(ip);
    if (reverseNames && reverseNames.length > 0) {
      // Check if any reverse DNS entry resolves back to the same IP
      const forwardCheck = await dns.resolve4(reverseNames[0]);
      if (!forwardCheck.includes(ip)) {
        result.reverseRecordMismatch = true;
      }
    }
  } catch {
    // No reverse DNS — common for cloud IPs, not necessarily bad
  }

  return result;
}

export async function checkThreatIntelForAssets(hostnames: string[]): Promise<ThreatIntelResult[]> {
  const results = await Promise.allSettled(
    hostnames.map((h) => checkThreatIntel(h))
  );

  return results
    .filter((r): r is PromiseFulfilledResult<ThreatIntelResult> => r.status === "fulfilled")
    .map((r) => r.value);
}
