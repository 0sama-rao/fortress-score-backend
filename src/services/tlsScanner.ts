import tls from "tls";
import { execFile } from "child_process";
import { promisify } from "util";
import type { TLSSignals } from "../types/scoring.js";

const execFileAsync = promisify(execFile);
const TLS_TIMEOUT = 10000;

export async function scanTLS(hostname: string): Promise<TLSSignals> {
  const signals: TLSSignals = {
    noCertificate: false,
    certificateExpired: false,
    daysUntilExpiry: 365,
    selfSigned: false,
    weakProtocol: false,
    weakCipher: false,
    wildcardCert: false,
    hostnameMismatch: false,
  };

  // 1. Connect with Node tls to get certificate info
  try {
    const cert = await getTLSCertificate(hostname);

    if (!cert) {
      signals.noCertificate = true;
      return signals;
    }

    // Check expiry
    const validTo = new Date(cert.valid_to);
    const now = new Date();
    const daysLeft = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    signals.daysUntilExpiry = daysLeft;
    signals.certificateExpired = daysLeft <= 0;

    // Check self-signed (issuer === subject)
    if (cert.issuer && cert.subject) {
      const issuerCN = typeof cert.issuer === "object" ? cert.issuer.CN : String(cert.issuer);
      const subjectCN = typeof cert.subject === "object" ? cert.subject.CN : String(cert.subject);
      signals.selfSigned = issuerCN === subjectCN;
    }

    // Check wildcard
    const cn = typeof cert.subject === "object" ? String(cert.subject.CN || "") : "";
    const altNames: string = cert.subjectaltname || "";
    signals.wildcardCert = cn.startsWith("*.") || altNames.includes("*.");

    // Check hostname mismatch
    if (cn && !altNames.includes(hostname) && cn !== hostname && !hostname.endsWith(cn.replace("*.", ""))) {
      signals.hostnameMismatch = true;
    }
  } catch {
    signals.noCertificate = true;
    return signals;
  }

  // 2. Check for weak protocols via openssl
  try {
    signals.weakProtocol = await checkWeakProtocols(hostname);
  } catch {
    // openssl not available or connection failed — skip
  }

  // 3. Check for weak ciphers
  try {
    signals.weakCipher = await checkWeakCiphers(hostname);
  } catch {
    // skip
  }

  return signals;
}

function getTLSCertificate(hostname: string): Promise<tls.PeerCertificate | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: TLS_TIMEOUT,
      },
      () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();
        resolve(cert && cert.subject ? cert : null);
      }
    );

    socket.on("error", () => {
      socket.destroy();
      resolve(null);
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve(null);
    });
  });
}

async function checkWeakProtocols(hostname: string): Promise<boolean> {
  // Try TLSv1.0 — if it connects, that's bad
  for (const protocol of ["-tls1", "-tls1_1"]) {
    try {
      await execFileAsync(
        "openssl",
        ["s_client", "-connect", `${hostname}:443`, protocol, "-servername", hostname],
        { timeout: TLS_TIMEOUT }
      );
      return true; // Connected with a weak protocol
    } catch {
      // Connection refused = good, protocol not supported
    }
  }
  return false;
}

async function checkWeakCiphers(hostname: string): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync(
      "openssl",
      ["s_client", "-connect", `${hostname}:443`, "-cipher", "RC4:DES:3DES", "-servername", hostname],
      { timeout: TLS_TIMEOUT }
    );
    // If it connected and we got a cipher line, weak cipher is supported
    return stdout.includes("Cipher is") && !stdout.includes("Cipher is (NONE)");
  } catch {
    return false;
  }
}
