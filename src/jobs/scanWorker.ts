import { Worker } from "bullmq";
import { PrismaClient } from "@prisma/client";
import { connection } from "../plugins/queue.js";
import { discoverAssets } from "../services/assetDiscovery.js";
import { scanTLS } from "../services/tlsScanner.js";
import { scanHeaders } from "../services/headerScanner.js";
import { scanNetwork } from "../services/networkScanner.js";
import { scanEmail } from "../services/emailScanner.js";
import { computeFortressScore } from "../services/scoringEngine.js";
import type { ScanJobPayload } from "../types/queue.js";
import type { TLSSignals, HeaderSignals, NetworkSignals, EmailSignals } from "../types/scoring.js";

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
        // ───────────────────────────────────
        // Step 1: Asset discovery
        // ───────────────────────────────────
        const assetCount = await discoverAssets(prisma, organizationId, rootDomain);
        console.log(`[scan:${scanId}] Discovered ${assetCount} assets for ${rootDomain}`);

        const assets = await prisma.asset.findMany({
          where: { organizationId },
        });

        if (assets.length === 0) {
          await prisma.scan.update({
            where: { id: scanId },
            data: { status: "COMPLETE", fortressScore: 0, completedAt: new Date() },
          });
          return;
        }

        // ───────────────────────────────────
        // Step 2: Run scanners per asset
        // ───────────────────────────────────
        const allTLS: TLSSignals[] = [];
        const allHeaders: HeaderSignals[] = [];
        const allNetwork: NetworkSignals[] = [];

        for (const asset of assets) {
          console.log(`[scan:${scanId}] Scanning ${asset.value}...`);

          // Run TLS + Headers + Network in parallel per asset
          // Use allSettled — one failing must not abort others
          const [tlsResult, headersResult, networkResult] = await Promise.allSettled([
            scanTLS(asset.value),
            scanHeaders(asset.value),
            scanNetwork(asset.value),
          ]);

          // Extract results (use defaults if scanner failed)
          const tlsSignals: TLSSignals = tlsResult.status === "fulfilled"
            ? tlsResult.value
            : { noCertificate: true, certificateExpired: false, daysUntilExpiry: 0, selfSigned: false, weakProtocol: false, weakCipher: false, wildcardCert: false, hostnameMismatch: false, noHttpsRedirect: false, longValidity: false, weakKeySize: null, weakSignature: false, untrustedCA: false };

          const headerSignals: HeaderSignals = headersResult.status === "fulfilled"
            ? headersResult.value
            : { missingHsts: true, missingCsp: true, missingXFrameOptions: true, missingXContentTypeOptions: true, missingXXssProtection: true, weakHstsMaxAge: false, weakCspPolicy: false, serverHeaderLeaksVersion: false };

          const networkSignals: NetworkSignals = networkResult.status === "fulfilled"
            ? networkResult.value
            : { openPorts: [], criticalPortsOpen: [], rdpExposed: false, sshExposed: false, telnetOpen: false, ftpOpen: false, smbExposed: false, dbPortsExposed: false, exposureFactor: 0 };

          allTLS.push(tlsSignals);
          allHeaders.push(headerSignals);
          allNetwork.push(networkSignals);

          // Store ScanResults per asset per category
          await Promise.all([
            prisma.scanResult.upsert({
              where: { scanId_assetId_category: { scanId, assetId: asset.id, category: "TLS" } },
              update: { riskScore: 0, signals: tlsSignals as object, scannedAt: new Date() },
              create: { scanId, assetId: asset.id, category: "TLS", riskScore: 0, signals: tlsSignals as object },
            }),
            prisma.scanResult.upsert({
              where: { scanId_assetId_category: { scanId, assetId: asset.id, category: "HEADERS" } },
              update: { riskScore: 0, signals: headerSignals as object, scannedAt: new Date() },
              create: { scanId, assetId: asset.id, category: "HEADERS", riskScore: 0, signals: headerSignals as object },
            }),
            prisma.scanResult.upsert({
              where: { scanId_assetId_category: { scanId, assetId: asset.id, category: "NETWORK" } },
              update: { riskScore: 0, signals: networkSignals as object, scannedAt: new Date() },
              create: { scanId, assetId: asset.id, category: "NETWORK", riskScore: 0, signals: networkSignals as object },
            }),
          ]);
        }

        // ───────────────────────────────────
        // Step 3: Email scan (root domain only, once)
        // ───────────────────────────────────
        const emailSignals = await scanEmail(rootDomain);

        // Store email result against the root domain asset
        const rootAsset = assets.find((a) => a.value === rootDomain) || assets[0];
        await prisma.scanResult.upsert({
          where: { scanId_assetId_category: { scanId, assetId: rootAsset.id, category: "EMAIL" } },
          update: { riskScore: 0, signals: emailSignals as object, scannedAt: new Date() },
          create: { scanId, assetId: rootAsset.id, category: "EMAIL", riskScore: 0, signals: emailSignals as object },
        });

        // ───────────────────────────────────
        // Step 4: Compute Fortress Score
        // ───────────────────────────────────
        const scores = computeFortressScore(allTLS, allHeaders, allNetwork, emailSignals);

        console.log(`[scan:${scanId}] Fortress Score: ${scores.fortressScore} (TLS:${scores.tlsScore} Headers:${scores.headersScore} Network:${scores.networkScore} Email:${scores.emailScore} Correlation:+${scores.correlationBonus})`);

        // Update individual ScanResult riskScores
        await prisma.$transaction([
          prisma.scanResult.updateMany({
            where: { scanId, category: "TLS" },
            data: { riskScore: scores.tlsScore },
          }),
          prisma.scanResult.updateMany({
            where: { scanId, category: "HEADERS" },
            data: { riskScore: scores.headersScore },
          }),
          prisma.scanResult.updateMany({
            where: { scanId, category: "NETWORK" },
            data: { riskScore: scores.networkScore },
          }),
          prisma.scanResult.updateMany({
            where: { scanId, category: "EMAIL" },
            data: { riskScore: scores.emailScore },
          }),
        ]);

        // ───────────────────────────────────
        // Step 5: Mark scan COMPLETE with scores
        // ───────────────────────────────────
        await prisma.scan.update({
          where: { id: scanId },
          data: {
            status: "COMPLETE",
            fortressScore: scores.fortressScore,
            tlsScore: scores.tlsScore,
            headersScore: scores.headersScore,
            networkScore: scores.networkScore,
            emailScore: scores.emailScore,
            completedAt: new Date(),
          },
        });

        console.log(`[scan:${scanId}] Completed successfully`);
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
