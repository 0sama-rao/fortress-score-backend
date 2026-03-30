import { promises as dns } from "dns";

// Known vulnerable CNAME patterns — if CNAME points to these and target doesn't resolve, takeover possible
const VULNERABLE_CNAMES: Record<string, string> = {
  "s3.amazonaws.com": "AWS S3",
  "s3-website": "AWS S3",
  ".cloudfront.net": "AWS CloudFront",
  ".elasticbeanstalk.com": "AWS Elastic Beanstalk",
  ".herokuapp.com": "Heroku",
  ".herokudns.com": "Heroku",
  "github.io": "GitHub Pages",
  ".ghost.io": "Ghost",
  ".myshopify.com": "Shopify",
  ".surge.sh": "Surge",
  ".bitbucket.io": "Bitbucket",
  ".netlify.app": "Netlify",
  ".netlify.com": "Netlify",
  ".wordpress.com": "WordPress",
  ".pantheon.io": "Pantheon",
  ".zendesk.com": "Zendesk",
  ".teamwork.com": "Teamwork",
  ".helpjuice.com": "HelpJuice",
  ".helpscoutdocs.com": "HelpScout",
  ".ghost.org": "Ghost",
  ".cargocollective.com": "Cargo",
  ".feedpress.me": "FeedPress",
  ".freshdesk.com": "Freshdesk",
  ".azurewebsites.net": "Azure",
  ".cloudapp.net": "Azure",
  ".trafficmanager.net": "Azure Traffic Manager",
  ".blob.core.windows.net": "Azure Blob Storage",
};

export interface TakeoverResult {
  hostname: string;
  vulnerable: boolean;
  cname: string | null;
  service: string | null;
}

export async function checkSubdomainTakeover(hostname: string): Promise<TakeoverResult> {
  const result: TakeoverResult = {
    hostname,
    vulnerable: false,
    cname: null,
    service: null,
  };

  try {
    // Get CNAME records
    const cnames = await dns.resolveCname(hostname);
    if (!cnames || cnames.length === 0) return result;

    const cnameTarget = cnames[0].toLowerCase();
    result.cname = cnameTarget;

    // Check if CNAME matches any known vulnerable pattern
    for (const [pattern, service] of Object.entries(VULNERABLE_CNAMES)) {
      if (cnameTarget.includes(pattern)) {
        // CNAME points to a known service — now check if the target is unclaimed
        try {
          await dns.resolve4(cnameTarget);
          // Target resolves — not vulnerable (service is active)
        } catch {
          // Target doesn't resolve — potential takeover!
          result.vulnerable = true;
          result.service = service;
        }
        break;
      }
    }
  } catch {
    // No CNAME record — not vulnerable to this attack
  }

  return result;
}

export async function checkTakeoverForAssets(hostnames: string[]): Promise<TakeoverResult[]> {
  const results = await Promise.allSettled(
    hostnames.map((h) => checkSubdomainTakeover(h))
  );

  return results
    .filter((r): r is PromiseFulfilledResult<TakeoverResult> => r.status === "fulfilled")
    .map((r) => r.value);
}
