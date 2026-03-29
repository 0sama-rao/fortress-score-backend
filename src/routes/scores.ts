import type { FastifyInstance } from "fastify";

export default async function scoresRoutes(app: FastifyInstance) {
  // GET /api/organizations/:orgId/score — current Fortress Score
  app.get(
    "/api/organizations/:orgId/score",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const { userId } = request.user;
      const { orgId } = request.params as { orgId: string };

      const org = await app.prisma.organization.findUnique({ where: { id: orgId } });
      if (!org) return reply.status(404).send({ error: "Organization not found" });
      if (org.userId !== userId) return reply.status(403).send({ error: "Forbidden" });

      // Get the most recent COMPLETE scan
      const latestScan = await app.prisma.scan.findFirst({
        where: { organizationId: orgId, status: "COMPLETE" },
        orderBy: { completedAt: "desc" },
      });

      if (!latestScan) {
        return reply.status(404).send({ error: "No completed scans yet" });
      }

      return reply.send({
        organizationId: orgId,
        fortressScore: latestScan.fortressScore,
        breakdown: {
          tls: { score: latestScan.tlsScore, weight: 0.30 },
          headers: { score: latestScan.headersScore, weight: 0.30 },
          network: { score: latestScan.networkScore, weight: 0.20 },
          email: { score: latestScan.emailScore, weight: 0.20 },
        },
        scanId: latestScan.id,
        scannedAt: latestScan.completedAt,
      });
    }
  );

  // GET /api/organizations/:orgId/score/history — trend data
  app.get(
    "/api/organizations/:orgId/score/history",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const { userId } = request.user;
      const { orgId } = request.params as { orgId: string };

      const org = await app.prisma.organization.findUnique({ where: { id: orgId } });
      if (!org) return reply.status(404).send({ error: "Organization not found" });
      if (org.userId !== userId) return reply.status(403).send({ error: "Forbidden" });

      const scans = await app.prisma.scan.findMany({
        where: { organizationId: orgId, status: "COMPLETE" },
        orderBy: { startedAt: "asc" },
        take: 90,
        select: {
          id: true,
          fortressScore: true,
          tlsScore: true,
          headersScore: true,
          networkScore: true,
          emailScore: true,
          startedAt: true,
          completedAt: true,
        },
      });

      return reply.send({
        organizationId: orgId,
        history: scans.map((s) => ({
          scanId: s.id,
          fortressScore: s.fortressScore,
          tlsScore: s.tlsScore,
          headersScore: s.headersScore,
          networkScore: s.networkScore,
          emailScore: s.emailScore,
          scannedAt: s.completedAt ?? s.startedAt,
        })),
      });
    }
  );
}
