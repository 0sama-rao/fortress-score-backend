import fp from "fastify-plugin";
import { Queue } from "bullmq";
import type { FastifyInstance } from "fastify";
import type { ScanJobPayload } from "../types/queue.js";

export const connection = {
  host: process.env.REDIS_HOST || "localhost",
  port: Number(process.env.REDIS_PORT) || 6379,
};

export default fp(async (app: FastifyInstance) => {
  const scanQueue = new Queue<ScanJobPayload>("scans", { connection });

  app.decorate("scanQueue", scanQueue);

  app.addHook("onClose", async () => {
    await scanQueue.close();
  });
});

declare module "fastify" {
  interface FastifyInstance {
    scanQueue: Queue<ScanJobPayload>;
  }
}
