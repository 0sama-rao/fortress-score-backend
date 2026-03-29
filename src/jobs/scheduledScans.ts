import { Queue, Worker } from "bullmq";
import { PrismaClient } from "@prisma/client";
import { connection } from "../plugins/queue.js";
import { addScanJob } from "./scanQueue.js";
import type { ScanJobPayload } from "../types/queue.js";

const prisma = new PrismaClient();

const SCHEDULED_SCAN_QUEUE = "scheduled-scans";

export function startScheduledScans() {
  const schedulerQueue = new Queue(SCHEDULED_SCAN_QUEUE, { connection });

  // Add a repeating job that triggers every 24 hours at 2 AM
  schedulerQueue.add(
    "daily-rescan",
    {},
    {
      repeat: { pattern: "0 2 * * *" },
      removeOnComplete: 10,
      removeOnFail: 10,
    }
  );

  const worker = new Worker(
    SCHEDULED_SCAN_QUEUE,
    async () => {
      console.log("[scheduler] Running daily rescan for all organizations...");

      const orgs = await prisma.organization.findMany();
      const mainQueue = new Queue<ScanJobPayload>("scans", { connection });

      for (const org of orgs) {
        // Skip if a scan is already running for this org
        const running = await prisma.scan.findFirst({
          where: { organizationId: org.id, status: { in: ["PENDING", "RUNNING"] } },
        });

        if (running) {
          console.log(`[scheduler] Skipping ${org.rootDomain} — scan already in progress`);
          continue;
        }

        const scan = await prisma.scan.create({
          data: { organizationId: org.id, status: "PENDING" },
        });

        await addScanJob(mainQueue, {
          scanId: scan.id,
          organizationId: org.id,
          rootDomain: org.rootDomain,
        });

        console.log(`[scheduler] Queued rescan for ${org.rootDomain} (scan: ${scan.id})`);
      }

      await mainQueue.close();
      console.log("[scheduler] Daily rescan dispatch complete");
    },
    { connection }
  );

  return { schedulerQueue, worker };
}
