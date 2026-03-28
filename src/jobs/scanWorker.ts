import { Worker } from "bullmq";
import { PrismaClient } from "@prisma/client";
import { connection, } from "../plugins/queue.js";
import { discoverAssets } from "../services/assetDiscovery.js";
import type { ScanJobPayload } from "../types/queue.js";

const prisma = new PrismaClient();

export function startScanWorker() {
  const worker = new Worker<ScanJobPayload>(
    "scans",
    async (job) => {
      const { scanId, organizationId, rootDomain } = job.data;

      // Mark scan as RUNNING
      await prisma.scan.update({
        where: { id: scanId },
        data: { status: "RUNNING" },
      });

      try {
        // Discover assets via crt.sh
        const assetCount = await discoverAssets(prisma, organizationId, rootDomain);

        console.log(`[scan:${scanId}] Discovered ${assetCount} assets for ${rootDomain}`);

        // Phase 2: mark complete without real scores
        // Phase 3 will replace this with real scanner results
        await prisma.scan.update({
          where: { id: scanId },
          data: {
            status: "COMPLETE",
            completedAt: new Date(),
          },
        });

        console.log(`[scan:${scanId}] Completed`);
      } catch (err) {
        console.error(`[scan:${scanId}] Failed:`, err);
        await prisma.scan.update({
          where: { id: scanId },
          data: { status: "FAILED", completedAt: new Date() },
        });
      }
    },
    {
      connection,
      concurrency: 2,
    }
  );

  worker.on("failed", (job, err) => {
    console.error(`[worker] Job ${job?.id} failed:`, err.message);
  });

  return worker;
}
