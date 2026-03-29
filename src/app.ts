import Fastify from "fastify";
import cors from "@fastify/cors";
import prismaPlugin from "./plugins/prisma.js";
import authPlugin from "./plugins/auth.js";
import queuePlugin from "./plugins/queue.js";
import authRoutes from "./routes/auth.js";
import organizationsRoutes from "./routes/organizations.js";
import scansRoutes from "./routes/scans.js";
import assetsRoutes from "./routes/assets.js";
import scoresRoutes from "./routes/scores.js";

export async function buildApp() {
  const app = Fastify({ logger: true });

  await app.register(cors, { origin: true });
  await app.register(prismaPlugin);
  await app.register(authPlugin);
  await app.register(queuePlugin);

  app.get("/api/health", async () => {
    return { status: "ok" };
  });

  await app.register(authRoutes);
  await app.register(organizationsRoutes);
  await app.register(scansRoutes);
  await app.register(assetsRoutes);
  await app.register(scoresRoutes);

  return app;
}
