import type { FastifyInstance } from "fastify";
import { addScanJob } from "../jobs/scanQueue.js";

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

      return reply.send({
        scanId: scan.id,
        status: scan.status,
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
