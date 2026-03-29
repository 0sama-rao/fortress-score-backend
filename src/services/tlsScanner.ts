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
    noHttpsRedirect: false,
    longValidity: false,
    weakKeySize: null,
    weakSignature: false,
    untrustedCA: false,
  };

  // 1. Connect with Node tls to get certificate info
  let cert: tls.PeerCertificate | null = null;
  try {
    cert = await getTLSCertificate(hostname);

    if (!cert) {
      signals.noCertificate = true;
      return signals;
    }

    // Check expiry
    const validTo = new Date(cert.valid_to);
    const validFrom = new Date(cert.valid_from);
    const now = new Date();
    const daysLeft = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    signals.daysUntilExpiry = daysLeft;
    signals.certificateExpired = daysLeft <= 0;

    // Check certificate validity > 398 days
    const validityDays = Math.floor((validTo.getTime() - validFrom.getTime()) / (1000 * 60 * 60 * 24));
    signals.longValidity = validityDays > 398;

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

  // 4. Check HTTP → HTTPS redirect
  try {
    signals.noHttpsRedirect = await checkNoHttpsRedirect(hostname);
  } catch {
    // skip
  }

  // 5. Check key size and signature algorithm via openssl
  try {
    const certDetails = await getCertDetails(hostname);
    signals.weakKeySize = certDetails.weakKeySize;
    signals.weakSignature = certDetails.weakSignature;
    signals.untrustedCA = certDetails.untrustedCA;
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
  for (const protocol of ["-tls1", "-tls1_1"]) {
    try {
      await execFileAsync(
        "openssl",
        ["s_client", "-connect", `${hostname}:443`, protocol, "-servername", hostname],
        { timeout: TLS_TIMEOUT }
      );
      return true;
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
    return stdout.includes("Cipher is") && !stdout.includes("Cipher is (NONE)");
  } catch {
    return false;
  }
}

async function checkNoHttpsRedirect(hostname: string): Promise<boolean> {
  try {
    const res = await fetch(`http://${hostname}`, {
      signal: AbortSignal.timeout(TLS_TIMEOUT),
      redirect: "manual",
    });
    // If HTTP responds without redirecting to HTTPS, that's a risk
    if (res.status >= 200 && res.status < 400) {
      const location = res.headers.get("location") || "";
      return !location.startsWith("https://");
    }
    return false;
  } catch {
    // HTTP not reachable — no redirect issue
    return false;
  }
}

async function getCertDetails(hostname: string): Promise<{
  weakKeySize: TLSSignals["weakKeySize"];
  weakSignature: boolean;
  untrustedCA: boolean;
}> {
  const result = { weakKeySize: null as TLSSignals["weakKeySize"], weakSignature: false, untrustedCA: false };

  // Get cert text via openssl
  try {
    const { stdout } = await execFileAsync(
      "openssl",
      ["s_client", "-connect", `${hostname}:443`, "-servername", hostname],
      { timeout: TLS_TIMEOUT }
    );

    // Check signature algorithm
    const sigMatch = stdout.match(/Signature Algorithm:\s*(\S+)/i);
    if (sigMatch) {
      const sig = sigMatch[1].toLowerCase();
      if (sig.includes("md2") || sig.includes("md5") || sig.includes("sha1")) {
        result.weakSignature = true;
      }
    }

    // Check key size
    const keyMatch = stdout.match(/Server public key is (\d+) bit/i);
    if (keyMatch) {
      const bits = parseInt(keyMatch[1], 10);
      const keyType = stdout.match(/Server Temp Key:\s*(\w+)/i)?.[1]?.toLowerCase() || "";

      if (keyType === "ecdh" || keyType === "ecdsa" || keyType === "ecc") {
        if (bits < 224) result.weakKeySize = "ecc224";
      } else if (keyType === "dsa") {
        if (bits < 2048) result.weakKeySize = "dsa2048";
      } else {
        // RSA or unknown — treat as RSA
        if (bits < 1024) result.weakKeySize = "rsa1024";
        else if (bits < 2048) result.weakKeySize = "rsa2048";
      }
    }

    // Check for untrusted CA (verify return code)
    const verifyMatch = stdout.match(/Verify return code:\s*(\d+)/);
    if (verifyMatch) {
      const code = parseInt(verifyMatch[1], 10);
      // 0 = ok, 18 = self-signed, 19 = self-signed in chain, 20 = unable to get local issuer cert
      if (code === 20 || code === 19 || code === 21) {
        result.untrustedCA = true;
      }
    }
  } catch {
    // skip
  }

  return result;
}
