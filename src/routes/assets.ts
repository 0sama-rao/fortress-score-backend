import type { FastifyInstance } from "fastify";

export default async function assetsRoutes(app: FastifyInstance) {
  // GET /api/organizations/:orgId/assets
  app.get(
    "/api/organizations/:orgId/assets",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const { userId } = request.user;
      const { orgId } = request.params as { orgId: string };

      const org = await app.prisma.organization.findUnique({ where: { id: orgId } });
      if (!org) return reply.status(404).send({ error: "Organization not found" });
      if (org.userId !== userId) return reply.status(403).send({ error: "Forbidden" });

      const assets = await app.prisma.asset.findMany({
        where: { organizationId: orgId },
        orderBy: { discoveredAt: "desc" },
      });

      return reply.send({ assets });
    }
  );
}
