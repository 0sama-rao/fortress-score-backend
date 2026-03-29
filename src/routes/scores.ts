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

      // Get previous scan for risk velocity
      const previousScan = await app.prisma.scan.findFirst({
        where: {
          organizationId: orgId,
          status: "COMPLETE",
          completedAt: { lt: latestScan.completedAt! },
        },
        orderBy: { completedAt: "desc" },
      });

      let riskVelocity: number | null = null;
      if (previousScan && latestScan.fortressScore !== null && previousScan.fortressScore !== null) {
        const timeDiffDays = latestScan.completedAt && previousScan.completedAt
          ? (latestScan.completedAt.getTime() - previousScan.completedAt.getTime()) / (1000 * 60 * 60 * 24)
          : 1;
        riskVelocity = timeDiffDays > 0
          ? Math.round(((latestScan.fortressScore - previousScan.fortressScore) / timeDiffDays) * 100) / 100
          : 0;
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
        riskVelocity,
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

      // Compute risk velocity for each point in history
      const history = scans.map((s, i) => {
        let riskVelocity: number | null = null;
        if (i > 0 && s.fortressScore !== null && scans[i - 1].fortressScore !== null) {
          const prev = scans[i - 1];
          const timeDiffDays = s.completedAt && prev.completedAt
            ? (s.completedAt.getTime() - prev.completedAt.getTime()) / (1000 * 60 * 60 * 24)
            : 1;
          riskVelocity = timeDiffDays > 0
            ? Math.round(((s.fortressScore! - prev.fortressScore!) / timeDiffDays) * 100) / 100
            : 0;
        }

        return {
          scanId: s.id,
          fortressScore: s.fortressScore,
          tlsScore: s.tlsScore,
          headersScore: s.headersScore,
          networkScore: s.networkScore,
          emailScore: s.emailScore,
          riskVelocity,
          scannedAt: s.completedAt ?? s.startedAt,
        };
      });

      return reply.send({
        organizationId: orgId,
        history,
      });
    }
  );
}
