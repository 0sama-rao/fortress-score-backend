/**
 * Business Impact Engine — translates technical findings into business risk insights.
 * Maps security signals to real-world business consequences.
 */

import type { TLSSignals, HeaderSignals, NetworkSignals, EmailSignals } from "../types/scoring.js";

export interface BusinessImpact {
  finding: string;
  impact: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  category: string;
}

export function computeBusinessImpact(
  tlsSignals: TLSSignals[],
  headerSignals: HeaderSignals[],
  networkSignals: NetworkSignals[],
  emailSignals: EmailSignals
): BusinessImpact[] {
  const impacts: BusinessImpact[] = [];

  // ── TLS impacts ──
  for (const tls of tlsSignals) {
    if (tls.noCertificate) {
      impacts.push({
        finding: "No TLS/SSL certificate",
        impact: "All data transmitted in plaintext — customer credentials, PII, and session tokens can be intercepted by attackers on the network path",
        severity: "CRITICAL",
        category: "Data Protection",
      });
    }
    if (tls.certificateExpired) {
      impacts.push({
        finding: "Expired SSL certificate",
        impact: "Browsers display security warnings deterring customers — direct revenue loss and brand damage. Man-in-the-middle attacks become possible",
        severity: "HIGH",
        category: "Business Continuity",
      });
    }
    if (tls.weakProtocol) {
      impacts.push({
        finding: "Weak TLS protocol (TLSv1.0/1.1)",
        impact: "Data interception risk via known protocol vulnerabilities (BEAST, POODLE). Non-compliant with PCI DSS 3.2+ requirements",
        severity: "HIGH",
        category: "Compliance",
      });
    }
    if (tls.noHttpsRedirect) {
      impacts.push({
        finding: "No HTTP to HTTPS redirect",
        impact: "Users accessing the site via HTTP transmit data unencrypted. Session hijacking and credential theft are possible",
        severity: "MEDIUM",
        category: "Data Protection",
      });
    }
    if (tls.weakSignature) {
      impacts.push({
        finding: "Weak certificate signature (MD5/SHA1)",
        impact: "Certificate can be forged using collision attacks — enables impersonation of your domain for phishing",
        severity: "HIGH",
        category: "Identity & Trust",
      });
    }
    if (tls.selfSigned) {
      impacts.push({
        finding: "Self-signed certificate",
        impact: "No third-party trust validation — susceptible to man-in-the-middle attacks. Browser warnings erode customer confidence",
        severity: "MEDIUM",
        category: "Identity & Trust",
      });
    }
  }

  // ── Network impacts ──
  for (const net of networkSignals) {
    if (net.rdpExposed) {
      impacts.push({
        finding: "Public RDP exposed",
        impact: "Risk of enterprise compromise via brute-force or credential stuffing. RDP is the #1 ransomware entry vector (used in 70%+ of incidents)",
        severity: "CRITICAL",
        category: "Ransomware Risk",
      });
    }
    if (net.telnetOpen) {
      impacts.push({
        finding: "Telnet port open",
        impact: "Credentials transmitted in plaintext. Indicates legacy infrastructure with likely unpatched vulnerabilities",
        severity: "HIGH",
        category: "Infrastructure Security",
      });
    }
    if (net.dbPortsExposed) {
      impacts.push({
        finding: "Database ports exposed to internet",
        impact: "Direct access to data stores — risk of data breach, data exfiltration, and regulatory penalties (GDPR fines up to 4% of revenue)",
        severity: "CRITICAL",
        category: "Data Breach Risk",
      });
    }
    if (net.ftpOpen) {
      impacts.push({
        finding: "FTP port open",
        impact: "File transfers in plaintext — credentials and sensitive files can be intercepted. Common malware distribution vector",
        severity: "HIGH",
        category: "Data Protection",
      });
    }
    if (net.smbExposed) {
      impacts.push({
        finding: "SMB exposed to internet",
        impact: "Risk of lateral movement attacks (WannaCry/NotPetya exploited SMB). Can lead to complete network compromise",
        severity: "CRITICAL",
        category: "Ransomware Risk",
      });
    }
  }

  // ── Header impacts ──
  for (const h of headerSignals) {
    if (h.missingCsp) {
      impacts.push({
        finding: "Missing Content-Security-Policy",
        impact: "Vulnerable to Cross-Site Scripting (XSS) attacks — attackers can inject malicious scripts to steal user sessions and data",
        severity: "MEDIUM",
        category: "Application Security",
      });
    }
    if (h.missingHsts) {
      impacts.push({
        finding: "Missing HSTS header",
        impact: "Users can be downgraded from HTTPS to HTTP via SSL stripping attacks, exposing all transmitted data",
        severity: "MEDIUM",
        category: "Data Protection",
      });
    }
  }

  // ── Email impacts ──
  if (emailSignals.spfMissing && emailSignals.dmarcMissing) {
    impacts.push({
      finding: "No SPF and no DMARC",
      impact: "Domain can be freely spoofed for phishing campaigns targeting customers, partners, and employees. High risk of business email compromise (BEC)",
      severity: "CRITICAL",
      category: "Phishing Exposure",
    });
  } else {
    if (emailSignals.dmarcMissing) {
      impacts.push({
        finding: "No DMARC policy",
        impact: "Email domain spoofing possible — attackers can send emails appearing to come from your domain for phishing and fraud",
        severity: "HIGH",
        category: "Phishing Exposure",
      });
    }
    if (emailSignals.spfMissing) {
      impacts.push({
        finding: "No SPF record",
        impact: "No sender validation — any server can send email as your domain. Enables targeted phishing campaigns",
        severity: "HIGH",
        category: "Phishing Exposure",
      });
    }
  }
  if (emailSignals.dmarcPolicyNone) {
    impacts.push({
      finding: "DMARC policy set to none",
      impact: "DMARC is monitoring-only — spoofed emails are still delivered. Provides visibility but no protection",
      severity: "MEDIUM",
      category: "Phishing Exposure",
    });
  }

  // Deduplicate by finding
  const seen = new Set<string>();
  return impacts.filter((i) => {
    if (seen.has(i.finding)) return false;
    seen.add(i.finding);
    return true;
  });
}
