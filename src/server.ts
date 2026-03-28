import "dotenv/config";
import { buildApp } from "./app.js";
import { startScanWorker } from "./jobs/scanWorker.js";

const PORT = Number(process.env.PORT) || 3000;

async function start() {
  const app = await buildApp();

  // Start BullMQ worker AFTER app is ready (DB connection established)
  const worker = startScanWorker();

  try {
    await app.listen({ port: PORT, host: "0.0.0.0" });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }

  const shutdown = async () => {
    await worker.close();
    await app.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

start();
