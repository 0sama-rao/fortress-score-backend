import type { FastifyInstance } from "fastify";

export default async function organizationsRoutes(app: FastifyInstance) {
  // GET /api/organizations
  app.get(
    "/api/organizations",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const { userId } = request.user;

      const organizations = await app.prisma.organization.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
      });

      return reply.send({ organizations });
    }
  );

  // POST /api/organizations
  app.post(
    "/api/organizations",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const { userId } = request.user;
      const { name, rootDomain } = request.body as {
        name: string;
        rootDomain: string;
      };

      if (!name || !rootDomain) {
        return reply.status(400).send({ error: "name and rootDomain are required" });
      }

      // Normalise: strip protocol, www., and trailing slashes
      const domain = rootDomain
        .replace(/^https?:\/\//i, "")
        .replace(/^www\./i, "")
        .replace(/\/+$/, "")
        .toLowerCase();

      const organization = await app.prisma.organization.create({
        data: { userId, name, rootDomain: domain },
      });

      return reply.status(201).send({ organization });
    }
  );

  // DELETE /api/organizations/:id
  app.delete(
    "/api/organizations/:id",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const { userId } = request.user;
      const { id } = request.params as { id: string };

      const org = await app.prisma.organization.findUnique({ where: { id } });

      if (!org) {
        return reply.status(404).send({ error: "Organization not found" });
      }

      if (org.userId !== userId) {
        return reply.status(403).send({ error: "Forbidden" });
      }

      await app.prisma.organization.delete({ where: { id } });

      return reply.status(204).send();
    }
  );
}
