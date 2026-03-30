import { Worker } from "bullmq";
import { PrismaClient } from "@prisma/client";
import { connection } from "../plugins/queue.js";
import { discoverAssets, lookupASNForAssets } from "../services/assetDiscovery.js";
import { scanTLS } from "../services/tlsScanner.js";
import { scanHeaders } from "../services/headerScanner.js";
import { scanNetwork } from "../services/networkScanner.js";
import { scanEmail } from "../services/emailScanner.js";
import { computeFortressScore } from "../services/scoringEngine.js";
import { checkTakeoverForAssets } from "../services/subdomainTakeover.js";
import { checkCloudBuckets } from "../services/cloudExposure.js";
import { checkThreatIntelForAssets } from "../services/threatIntel.js";
import { checkVulnIntel } from "../services/vulnIntel.js";
import { computeBusinessImpact } from "../services/businessImpact.js";
import type { ScanJobPayload } from "../types/queue.js";
import type { TLSSignals, HeaderSignals, NetworkSignals, EmailSignals } from "../types/scoring.js";

const prisma = new PrismaClient();

const CRITICAL_PORTS: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC",
  1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
  27017: "MongoDB", 445: "SMB",
};

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
        // Step 2: Run core scanners per asset
        // ───────────────────────────────────
        const allTLS: TLSSignals[] = [];
        const allHeaders: HeaderSignals[] = [];
        const allNetwork: NetworkSignals[] = [];

        for (const asset of assets) {
          console.log(`[scan:${scanId}] Scanning ${asset.value}...`);

          const [tlsResult, headersResult, networkResult] = await Promise.allSettled([
            scanTLS(asset.value),
            scanHeaders(asset.value),
            scanNetwork(asset.value),
          ]);

          const tlsSignals: TLSSignals = tlsResult.status === "fulfilled"
            ? tlsResult.value
            : { noCertificate: true, certificateExpired: false, daysUntilExpiry: 0, selfSigned: false, weakProtocol: false, weakCipher: false, wildcardCert: false, hostnameMismatch: false, noHttpsRedirect: false, longValidity: false, weakKeySize: null, weakSignature: false, untrustedCA: false };

          const headerSignals: HeaderSignals = headersResult.status === "fulfilled"
            ? headersResult.value
            : { missingHsts: true, missingCsp: true, missingXFrameOptions: true, missingXContentTypeOptions: true, missingXXssProtection: true, weakHstsMaxAge: false, weakCspPolicy: false, serverHeaderLeaksVersion: false };

          const networkSignals: NetworkSignals = networkResult.status === "fulfilled"
            ? networkResult.value
            : { openPorts: [], criticalPortsOpen: [], rdpExposed: false, sshExposed: false, telnetOpen: false, ftpOpen: false, smbExposed: false, dbPortsExposed: false, multipleWebPorts: false, exposureFactor: 0 };

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

        const rootAsset = assets.find((a) => a.value === rootDomain) || assets[0];
        await prisma.scanResult.upsert({
          where: { scanId_assetId_category: { scanId, assetId: rootAsset.id, category: "EMAIL" } },
          update: { riskScore: 0, signals: emailSignals as object, scannedAt: new Date() },
          create: { scanId, assetId: rootAsset.id, category: "EMAIL", riskScore: 0, signals: emailSignals as object },
        });

        // ───────────────────────────────────
        // Step 4: Phase 3 — Advanced Intelligence (parallel)
        // ───────────────────────────────────
        const hostnames = assets.map((a) => a.value);

        // Collect exposed services from network scans
        const exposedServices = new Set<string>();
        for (const net of allNetwork) {
          for (const port of net.openPorts) {
            if (port in CRITICAL_PORTS) {
              exposedServices.add(CRITICAL_PORTS[port]);
            }
          }
        }

        // Wrap all intelligence in a 30s timeout — don't let it slow down the scan
        const intelTimeout = <T>(promise: Promise<T>, fallback: T): Promise<T> =>
          Promise.race([promise, new Promise<T>((resolve) => setTimeout(() => resolve(fallback), 30000))]);

        const [takeoverResults, cloudResults, threatResults, vulnResults, asnResults] = await Promise.allSettled([
          intelTimeout(checkTakeoverForAssets(hostnames.slice(0, 10)), []),
          intelTimeout(checkCloudBuckets(rootDomain), []),
          intelTimeout(checkThreatIntelForAssets(hostnames.slice(0, 5)), []),
          intelTimeout(checkVulnIntel([...exposedServices]), { totalKEVMatches: 0, kevFindings: [], servicesChecked: [] }),
          intelTimeout(lookupASNForAssets(hostnames.slice(0, 5)), new Map()),
        ]);

        // Store Phase 3 results as a special scan result on the root asset
        const advancedIntel = {
          subdomainTakeover: takeoverResults.status === "fulfilled"
            ? takeoverResults.value.filter((r) => r.vulnerable) : [],
          cloudExposure: cloudResults.status === "fulfilled"
            ? cloudResults.value : [],
          threatIntel: threatResults.status === "fulfilled"
            ? threatResults.value.filter((r) => r.inDnsBlocklist) : [],
          vulnIntel: vulnResults.status === "fulfilled"
            ? vulnResults.value : { totalKEVMatches: 0, kevFindings: [], servicesChecked: [] },
          asnInfo: asnResults.status === "fulfilled"
            ? Object.fromEntries(asnResults.value) : {},
        };

        console.log(`[scan:${scanId}] Intelligence: ${advancedIntel.subdomainTakeover.length} takeover risks, ${advancedIntel.cloudExposure.length} exposed buckets, ${advancedIntel.threatIntel.length} blocklisted IPs, ${advancedIntel.vulnIntel.totalKEVMatches} KEV matches`);

        // ───────────────────────────────────
        // Step 5: Business Impact
        // ───────────────────────────────────
        const businessImpacts = computeBusinessImpact(allTLS, allHeaders, allNetwork, emailSignals);

        // ───────────────────────────────────
        // Step 6: Compute Fortress Score
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
        // Step 7: Mark scan COMPLETE with scores
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
            intelligenceData: advancedIntel as object,
            businessImpactData: businessImpacts as object,
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
