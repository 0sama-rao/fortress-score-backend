import { Queue } from "bullmq";
import { connection } from "../plugins/queue.js";
import type { ScanJobPayload } from "../types/queue.js";

export const SCAN_QUEUE_NAME = "scans";

export function createScanQueue() {
  return new Queue<ScanJobPayload>(SCAN_QUEUE_NAME, { connection });
}

export async function addScanJob(queue: Queue<ScanJobPayload>, payload: ScanJobPayload) {
  return queue.add("scan", payload, {
    removeOnComplete: 100,
    removeOnFail: 50,
  });
}
