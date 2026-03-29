import type { FastifyInstance } from "fastify";
import { addScanJob } from "../jobs/scanQueue.js";

interface ScanWithResults {
  fortressScore: number | null;
  tlsScore: number | null;
  headersScore: number | null;
  networkScore: number | null;
  emailScore: number | null;
  results: Array<{
    category: string;
    riskScore: number;
    signals: unknown;
    asset: { value: string };
  }>;
  organization: { name: string; rootDomain: string };
}

function buildExecutiveSummary(scan: ScanWithResults) {
  const issues: string[] = [];
  const fixes: string[] = [];

  for (const r of scan.results) {
    const signals = r.signals as Record<string, unknown>;
    if (!signals) continue;

    if (r.category === "TLS") {
      if (signals.noCertificate) { issues.push(`No TLS certificate on ${r.asset.value}`); fixes.push("Enable TLS/SSL on all public endpoints"); }
      if (signals.certificateExpired) { issues.push(`Expired certificate on ${r.asset.value}`); fixes.push("Renew expired TLS certificates"); }
      if (signals.weakProtocol) { issues.push("Weak TLS protocol (TLSv1/1.1) supported"); fixes.push("Disable TLSv1.0 and TLSv1.1 support"); }
      if (signals.weakCipher) { issues.push("Weak cipher suites (RC4/DES/3DES) accepted"); fixes.push("Remove weak cipher suites from server configuration"); }
      if (signals.noHttpsRedirect) { issues.push("No HTTP to HTTPS redirect"); fixes.push("Configure HTTP to HTTPS redirect on all web servers"); }
      if (signals.weakSignature) { issues.push("Weak certificate signature algorithm (MD5/SHA1)"); fixes.push("Reissue certificates with SHA-256 or stronger signature"); }
      if (signals.selfSigned) { issues.push(`Self-signed certificate on ${r.asset.value}`); fixes.push("Replace self-signed certificates with trusted CA-issued ones"); }
    }

    if (r.category === "HEADERS") {
      if (signals.missingCsp) { issues.push("Missing Content-Security-Policy header"); fixes.push("Implement Content-Security-Policy header"); }
      if (signals.missingHsts) { issues.push("Missing Strict-Transport-Security header"); fixes.push("Deploy HSTS with min 6-month max-age"); }
      if (signals.weakCspPolicy) { issues.push("Weak CSP policy (unsafe-inline/unsafe-eval)"); fixes.push("Tighten CSP policy to remove unsafe directives"); }
    }

    if (r.category === "NETWORK") {
      if (signals.rdpExposed) { issues.push("Public RDP exposed"); fixes.push("Disable public RDP access or restrict to VPN"); }
      if (signals.telnetOpen) { issues.push("Telnet port open"); fixes.push("Disable Telnet and use SSH instead"); }
      if (signals.ftpOpen) { issues.push("FTP port open"); fixes.push("Replace FTP with SFTP/SCP"); }
      if (signals.dbPortsExposed) { issues.push("Database ports exposed to internet"); fixes.push("Restrict database access to internal networks only"); }
      if (signals.smbExposed) { issues.push("SMB port exposed"); fixes.push("Block SMB (port 445) from public access"); }
    }

    if (r.category === "EMAIL") {
      if (signals.spfMissing) { issues.push("No SPF record"); fixes.push("Add SPF record to DNS"); }
      if (signals.dmarcMissing) { issues.push("No DMARC policy"); fixes.push("Deploy DMARC with reject policy"); }
      if (signals.dkimMissing) { issues.push("No DKIM record found"); fixes.push("Configure DKIM signing for outbound email"); }
      if (signals.dmarcPolicyNone) { issues.push("DMARC policy set to none"); fixes.push("Upgrade DMARC policy from none to quarantine/reject"); }
    }
  }

  // Deduplicate
  const uniqueIssues = [...new Set(issues)];
  const uniqueFixes = [...new Set(fixes)];

  // Score label
  const score = scan.fortressScore ?? 0;
  let posture = "Excellent";
  if (score > 80) posture = "Critical";
  else if (score > 60) posture = "High Risk";
  else if (score > 40) posture = "Moderate";
  else if (score > 20) posture = "Good";

  return {
    company: scan.organization.name,
    domain: scan.organization.rootDomain,
    fortressScore: scan.fortressScore,
    posture,
    keyIssues: uniqueIssues.slice(0, 10),
    recommendedFixes: uniqueFixes.slice(0, 10),
  };
}

export default async function scansRoutes(app: FastifyInstance) {
  // POST /api/scans — trigger a new scan
  app.post(
    "/api/scans",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const { userId } = request.user;
      const { organizationId } = request.body as { organizationId: string };

      if (!organizationId) {
        return reply.status(400).send({ error: "organizationId is required" });
      }

      // Verify org belongs to this user
      const org = await app.prisma.organization.findUnique({
        where: { id: organizationId },
      });

      if (!org) {
        return reply.status(404).send({ error: "Organization not found" });
      }

      if (org.userId !== userId) {
        return reply.status(403).send({ error: "Forbidden" });
      }

      // Check no scan is already running for this org
      const running = await app.prisma.scan.findFirst({
        where: { organizationId, status: { in: ["PENDING", "RUNNING"] } },
      });

      if (running) {
        return reply.status(409).send({
          error: "A scan is already in progress for this organization",
          scanId: running.id,
        });
      }

      // Create scan record
      const scan = await app.prisma.scan.create({
        data: { organizationId, status: "PENDING" },
      });

      // Push to BullMQ
      await addScanJob(app.scanQueue, {
        scanId: scan.id,
        organizationId,
        rootDomain: org.rootDomain,
      });

      return reply.status(201).send({
        id: scan.id,
        organizationId: scan.organizationId,
        status: scan.status,
        startedAt: scan.startedAt,
      });
    }
  );

  // GET /api/scans/:id — poll scan status
  app.get(
    "/api/scans/:id",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const { userId } = request.user;
      const { id } = request.params as { id: string };

      const scan = await app.prisma.scan.findUnique({
        where: { id },
        include: { organization: true },
      });

      if (!scan) {
        return reply.status(404).send({ error: "Scan not found" });
      }

      if (scan.organization.userId !== userId) {
        return reply.status(403).send({ error: "Forbidden" });
      }

      return reply.send({
        id: scan.id,
        organizationId: scan.organizationId,
        status: scan.status,
        fortressScore: scan.fortressScore,
        tlsScore: scan.tlsScore,
        headersScore: scan.headersScore,
        networkScore: scan.networkScore,
        emailScore: scan.emailScore,
        startedAt: scan.startedAt,
        completedAt: scan.completedAt,
      });
    }
  );

  // GET /api/scans/:id/results — full findings per asset
  app.get(
    "/api/scans/:id/results",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const { userId } = request.user;
      const { id } = request.params as { id: string };

      const scan = await app.prisma.scan.findUnique({
        where: { id },
        include: {
          organization: true,
          results: { include: { asset: true } },
        },
      });

      if (!scan) {
        return reply.status(404).send({ error: "Scan not found" });
      }

      if (scan.organization.userId !== userId) {
        return reply.status(403).send({ error: "Forbidden" });
      }

      // Build executive summary from findings
      const executiveSummary = buildExecutiveSummary(scan);

      return reply.send({
        scanId: scan.id,
        status: scan.status,
        fortressScore: scan.fortressScore,
        executiveSummary,
        results: scan.results.map((r) => ({
          id: r.id,
          assetId: r.assetId,
          assetValue: r.asset.value,
          category: r.category,
          riskScore: r.riskScore,
          signals: r.signals,
          scannedAt: r.scannedAt,
        })),
      });
    }
  );

  // GET /api/organizations/:orgId/scans — list scans for an org
  app.get(
    "/api/organizations/:orgId/scans",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const { userId } = request.user;
      const { orgId } = request.params as { orgId: string };

      const org = await app.prisma.organization.findUnique({ where: { id: orgId } });
      if (!org) return reply.status(404).send({ error: "Organization not found" });
      if (org.userId !== userId) return reply.status(403).send({ error: "Forbidden" });

      const scans = await app.prisma.scan.findMany({
        where: { organizationId: orgId },
        orderBy: { startedAt: "desc" },
        take: 20,
      });

      return reply.send({ scans });
    }
  );
}
